rule TTP_XOR_QUAD_CurrentVersionRun_6b39 {
  strings:
    $key_6b39 = { 38 56 [2] 1c 58 [2] 37 74 [2] 19 56 [2] 0d 4d [2] 02 57 [2] 1c 4a [2] 1e 4b [2] 05 4d [2] 19 4a [2] 05 65 }

  condition:
    any of them
}