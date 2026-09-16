rule TTP_XOR_QUAD_CurrentVersionRun_3c37 {
  strings:
    $key_3c37 = { 6f 58 [2] 4b 56 [2] 60 7a [2] 4e 58 [2] 5a 43 [2] 55 59 [2] 4b 44 [2] 49 45 [2] 52 43 [2] 4e 44 [2] 52 6b }

  condition:
    any of them
}