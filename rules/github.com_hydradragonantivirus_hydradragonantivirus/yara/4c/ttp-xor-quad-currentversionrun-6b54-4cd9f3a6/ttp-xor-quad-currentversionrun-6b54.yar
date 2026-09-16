rule TTP_XOR_QUAD_CurrentVersionRun_6b54 {
  strings:
    $key_6b54 = { 38 3b [2] 1c 35 [2] 37 19 [2] 19 3b [2] 0d 20 [2] 02 3a [2] 1c 27 [2] 1e 26 [2] 05 20 [2] 19 27 [2] 05 08 }

  condition:
    any of them
}