rule TTP_XOR_QUAD_CurrentVersionRun_35e4 {
  strings:
    $key_35e4 = { 66 8b [2] 42 85 [2] 69 a9 [2] 47 8b [2] 53 90 [2] 5c 8a [2] 42 97 [2] 40 96 [2] 5b 90 [2] 47 97 [2] 5b b8 }

  condition:
    any of them
}