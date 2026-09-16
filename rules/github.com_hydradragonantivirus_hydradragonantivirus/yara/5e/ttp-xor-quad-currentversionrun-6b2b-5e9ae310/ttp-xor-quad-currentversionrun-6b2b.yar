rule TTP_XOR_QUAD_CurrentVersionRun_6b2b {
  strings:
    $key_6b2b = { 38 44 [2] 1c 4a [2] 37 66 [2] 19 44 [2] 0d 5f [2] 02 45 [2] 1c 58 [2] 1e 59 [2] 05 5f [2] 19 58 [2] 05 77 }

  condition:
    any of them
}