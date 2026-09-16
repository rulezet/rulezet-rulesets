rule TTP_XOR_QUAD_CurrentVersionRun_6b6d {
  strings:
    $key_6b6d = { 38 02 [2] 1c 0c [2] 37 20 [2] 19 02 [2] 0d 19 [2] 02 03 [2] 1c 1e [2] 1e 1f [2] 05 19 [2] 19 1e [2] 05 31 }

  condition:
    any of them
}