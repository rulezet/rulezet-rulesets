rule TTP_XOR_QUAD_CurrentVersionRun_a530 {
  strings:
    $key_a530 = { f6 5f [2] d2 51 [2] f9 7d [2] d7 5f [2] c3 44 [2] cc 5e [2] d2 43 [2] d0 42 [2] cb 44 [2] d7 43 [2] cb 6c }

  condition:
    any of them
}