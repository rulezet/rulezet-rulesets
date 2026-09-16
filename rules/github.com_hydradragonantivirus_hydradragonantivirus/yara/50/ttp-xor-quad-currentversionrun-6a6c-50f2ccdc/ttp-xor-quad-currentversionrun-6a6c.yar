rule TTP_XOR_QUAD_CurrentVersionRun_6a6c {
  strings:
    $key_6a6c = { 39 03 [2] 1d 0d [2] 36 21 [2] 18 03 [2] 0c 18 [2] 03 02 [2] 1d 1f [2] 1f 1e [2] 04 18 [2] 18 1f [2] 04 30 }

  condition:
    any of them
}