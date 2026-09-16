rule TTP_XOR_QUAD_CurrentVersionRun_e4e4 {
  strings:
    $key_e4e4 = { b7 8b [2] 93 85 [2] b8 a9 [2] 96 8b [2] 82 90 [2] 8d 8a [2] 93 97 [2] 91 96 [2] 8a 90 [2] 96 97 [2] 8a b8 }

  condition:
    any of them
}