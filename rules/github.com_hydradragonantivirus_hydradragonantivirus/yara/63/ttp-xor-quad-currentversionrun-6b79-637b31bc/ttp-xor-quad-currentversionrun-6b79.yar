rule TTP_XOR_QUAD_CurrentVersionRun_6b79 {
  strings:
    $key_6b79 = { 38 16 [2] 1c 18 [2] 37 34 [2] 19 16 [2] 0d 0d [2] 02 17 [2] 1c 0a [2] 1e 0b [2] 05 0d [2] 19 0a [2] 05 25 }

  condition:
    any of them
}