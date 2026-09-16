rule TTP_XOR_QUAD_CurrentVersionRun_ecf9 {
  strings:
    $key_ecf9 = { bf 96 [2] 9b 98 [2] b0 b4 [2] 9e 96 [2] 8a 8d [2] 85 97 [2] 9b 8a [2] 99 8b [2] 82 8d [2] 9e 8a [2] 82 a5 }

  condition:
    any of them
}