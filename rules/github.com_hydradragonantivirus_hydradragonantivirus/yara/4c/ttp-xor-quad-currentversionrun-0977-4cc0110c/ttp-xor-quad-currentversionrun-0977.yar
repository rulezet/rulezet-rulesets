rule TTP_XOR_QUAD_CurrentVersionRun_0977 {
  strings:
    $key_0977 = { 5a 18 [2] 7e 16 [2] 55 3a [2] 7b 18 [2] 6f 03 [2] 60 19 [2] 7e 04 [2] 7c 05 [2] 67 03 [2] 7b 04 [2] 67 2b }

  condition:
    any of them
}