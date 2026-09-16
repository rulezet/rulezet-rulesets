rule TTP_XOR_QUAD_CurrentVersionRun_394b {
  strings:
    $key_394b = { 6a 24 [2] 4e 2a [2] 65 06 [2] 4b 24 [2] 5f 3f [2] 50 25 [2] 4e 38 [2] 4c 39 [2] 57 3f [2] 4b 38 [2] 57 17 }

  condition:
    any of them
}