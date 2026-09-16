rule TTP_XOR_QUAD_CurrentVersionRun_ece4 {
  strings:
    $key_ece4 = { bf 8b [2] 9b 85 [2] b0 a9 [2] 9e 8b [2] 8a 90 [2] 85 8a [2] 9b 97 [2] 99 96 [2] 82 90 [2] 9e 97 [2] 82 b8 }

  condition:
    any of them
}