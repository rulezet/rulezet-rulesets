rule TTP_XOR_QUAD_CurrentVersionRun_ebf8 {
  strings:
    $key_ebf8 = { b8 97 [2] 9c 99 [2] b7 b5 [2] 99 97 [2] 8d 8c [2] 82 96 [2] 9c 8b [2] 9e 8a [2] 85 8c [2] 99 8b [2] 85 a4 }

  condition:
    any of them
}