rule TTP_XOR_QUAD_CurrentVersionRun_763b {
  strings:
    $key_763b = { 25 54 [2] 01 5a [2] 2a 76 [2] 04 54 [2] 10 4f [2] 1f 55 [2] 01 48 [2] 03 49 [2] 18 4f [2] 04 48 [2] 18 67 }

  condition:
    any of them
}