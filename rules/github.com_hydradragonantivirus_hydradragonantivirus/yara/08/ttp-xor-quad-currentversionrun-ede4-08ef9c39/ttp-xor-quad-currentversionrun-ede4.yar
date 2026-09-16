rule TTP_XOR_QUAD_CurrentVersionRun_ede4 {
  strings:
    $key_ede4 = { be 8b [2] 9a 85 [2] b1 a9 [2] 9f 8b [2] 8b 90 [2] 84 8a [2] 9a 97 [2] 98 96 [2] 83 90 [2] 9f 97 [2] 83 b8 }

  condition:
    any of them
}