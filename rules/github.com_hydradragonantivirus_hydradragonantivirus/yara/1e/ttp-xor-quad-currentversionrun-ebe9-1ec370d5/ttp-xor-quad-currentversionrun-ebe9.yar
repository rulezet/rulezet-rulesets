rule TTP_XOR_QUAD_CurrentVersionRun_ebe9 {
  strings:
    $key_ebe9 = { b8 86 [2] 9c 88 [2] b7 a4 [2] 99 86 [2] 8d 9d [2] 82 87 [2] 9c 9a [2] 9e 9b [2] 85 9d [2] 99 9a [2] 85 b5 }

  condition:
    any of them
}