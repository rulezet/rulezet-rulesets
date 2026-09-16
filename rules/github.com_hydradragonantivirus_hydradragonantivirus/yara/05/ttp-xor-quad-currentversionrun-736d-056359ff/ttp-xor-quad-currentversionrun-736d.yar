rule TTP_XOR_QUAD_CurrentVersionRun_736d {
  strings:
    $key_736d = { 20 02 [2] 04 0c [2] 2f 20 [2] 01 02 [2] 15 19 [2] 1a 03 [2] 04 1e [2] 06 1f [2] 1d 19 [2] 01 1e [2] 1d 31 }

  condition:
    any of them
}