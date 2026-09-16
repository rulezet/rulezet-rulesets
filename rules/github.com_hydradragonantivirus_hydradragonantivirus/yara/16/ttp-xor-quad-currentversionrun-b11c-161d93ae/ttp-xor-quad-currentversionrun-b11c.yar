rule TTP_XOR_QUAD_CurrentVersionRun_b11c {
  strings:
    $key_b11c = { e2 73 [2] c6 7d [2] ed 51 [2] c3 73 [2] d7 68 [2] d8 72 [2] c6 6f [2] c4 6e [2] df 68 [2] c3 6f [2] df 40 }

  condition:
    any of them
}