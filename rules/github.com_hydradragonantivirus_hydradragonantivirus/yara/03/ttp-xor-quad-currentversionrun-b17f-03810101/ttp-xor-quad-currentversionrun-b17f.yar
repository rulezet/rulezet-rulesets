rule TTP_XOR_QUAD_CurrentVersionRun_b17f {
  strings:
    $key_b17f = { e2 10 [2] c6 1e [2] ed 32 [2] c3 10 [2] d7 0b [2] d8 11 [2] c6 0c [2] c4 0d [2] df 0b [2] c3 0c [2] df 23 }

  condition:
    any of them
}