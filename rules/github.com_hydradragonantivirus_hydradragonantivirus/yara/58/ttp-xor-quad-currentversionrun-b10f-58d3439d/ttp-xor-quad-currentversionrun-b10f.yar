rule TTP_XOR_QUAD_CurrentVersionRun_b10f {
  strings:
    $key_b10f = { e2 60 [2] c6 6e [2] ed 42 [2] c3 60 [2] d7 7b [2] d8 61 [2] c6 7c [2] c4 7d [2] df 7b [2] c3 7c [2] df 53 }

  condition:
    any of them
}