rule TTP_XOR_QUAD_CurrentVersionRun_ece5 {
  strings:
    $key_ece5 = { bf 8a [2] 9b 84 [2] b0 a8 [2] 9e 8a [2] 8a 91 [2] 85 8b [2] 9b 96 [2] 99 97 [2] 82 91 [2] 9e 96 [2] 82 b9 }

  condition:
    any of them
}