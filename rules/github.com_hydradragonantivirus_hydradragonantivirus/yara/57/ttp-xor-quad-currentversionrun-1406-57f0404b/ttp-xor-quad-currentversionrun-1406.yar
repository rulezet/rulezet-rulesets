rule TTP_XOR_QUAD_CurrentVersionRun_1406 {
  strings:
    $key_1406 = { 47 69 [2] 63 67 [2] 48 4b [2] 66 69 [2] 72 72 [2] 7d 68 [2] 63 75 [2] 61 74 [2] 7a 72 [2] 66 75 [2] 7a 5a }

  condition:
    any of them
}