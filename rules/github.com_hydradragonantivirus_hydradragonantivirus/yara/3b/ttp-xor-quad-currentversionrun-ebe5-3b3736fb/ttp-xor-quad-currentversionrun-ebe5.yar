rule TTP_XOR_QUAD_CurrentVersionRun_ebe5 {
  strings:
    $key_ebe5 = { b8 8a [2] 9c 84 [2] b7 a8 [2] 99 8a [2] 8d 91 [2] 82 8b [2] 9c 96 [2] 9e 97 [2] 85 91 [2] 99 96 [2] 85 b9 }

  condition:
    any of them
}