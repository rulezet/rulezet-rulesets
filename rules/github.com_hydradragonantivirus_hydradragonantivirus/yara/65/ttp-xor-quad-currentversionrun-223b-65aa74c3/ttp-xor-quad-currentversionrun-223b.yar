rule TTP_XOR_QUAD_CurrentVersionRun_223b {
  strings:
    $key_223b = { 71 54 [2] 55 5a [2] 7e 76 [2] 50 54 [2] 44 4f [2] 4b 55 [2] 55 48 [2] 57 49 [2] 4c 4f [2] 50 48 [2] 4c 67 }

  condition:
    any of them
}