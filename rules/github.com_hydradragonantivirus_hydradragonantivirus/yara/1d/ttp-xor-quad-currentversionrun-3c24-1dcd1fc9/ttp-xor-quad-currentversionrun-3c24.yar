rule TTP_XOR_QUAD_CurrentVersionRun_3c24 {
  strings:
    $key_3c24 = { 6f 4b [2] 4b 45 [2] 60 69 [2] 4e 4b [2] 5a 50 [2] 55 4a [2] 4b 57 [2] 49 56 [2] 52 50 [2] 4e 57 [2] 52 78 }

  condition:
    any of them
}