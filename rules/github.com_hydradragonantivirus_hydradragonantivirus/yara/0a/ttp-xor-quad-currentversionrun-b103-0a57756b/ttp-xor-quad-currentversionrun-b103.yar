rule TTP_XOR_QUAD_CurrentVersionRun_b103 {
  strings:
    $key_b103 = { e2 6c [2] c6 62 [2] ed 4e [2] c3 6c [2] d7 77 [2] d8 6d [2] c6 70 [2] c4 71 [2] df 77 [2] c3 70 [2] df 5f }

  condition:
    any of them
}