rule TTP_XOR_QUAD_CurrentVersionRun_ebfa {
  strings:
    $key_ebfa = { b8 95 [2] 9c 9b [2] b7 b7 [2] 99 95 [2] 8d 8e [2] 82 94 [2] 9c 89 [2] 9e 88 [2] 85 8e [2] 99 89 [2] 85 a6 }

  condition:
    any of them
}