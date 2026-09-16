rule TTP_XOR_QUAD_CurrentVersionRun_12e4 {
  strings:
    $key_12e4 = { 41 8b [2] 65 85 [2] 4e a9 [2] 60 8b [2] 74 90 [2] 7b 8a [2] 65 97 [2] 67 96 [2] 7c 90 [2] 60 97 [2] 7c b8 }

  condition:
    any of them
}