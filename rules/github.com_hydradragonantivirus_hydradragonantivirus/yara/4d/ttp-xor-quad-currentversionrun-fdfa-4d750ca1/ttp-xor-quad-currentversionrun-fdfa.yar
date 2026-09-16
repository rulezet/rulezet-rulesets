rule TTP_XOR_QUAD_CurrentVersionRun_fdfa {
  strings:
    $key_fdfa = { ae 95 [2] 8a 9b [2] a1 b7 [2] 8f 95 [2] 9b 8e [2] 94 94 [2] 8a 89 [2] 88 88 [2] 93 8e [2] 8f 89 [2] 93 a6 }

  condition:
    any of them
}