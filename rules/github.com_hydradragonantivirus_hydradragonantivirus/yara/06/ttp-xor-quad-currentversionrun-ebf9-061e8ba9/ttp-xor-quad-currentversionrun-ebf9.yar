rule TTP_XOR_QUAD_CurrentVersionRun_ebf9 {
  strings:
    $key_ebf9 = { b8 96 [2] 9c 98 [2] b7 b4 [2] 99 96 [2] 8d 8d [2] 82 97 [2] 9c 8a [2] 9e 8b [2] 85 8d [2] 99 8a [2] 85 a5 }

  condition:
    any of them
}