rule TTP_XOR_QUAD_CurrentVersionRun_b10c {
  strings:
    $key_b10c = { e2 63 [2] c6 6d [2] ed 41 [2] c3 63 [2] d7 78 [2] d8 62 [2] c6 7f [2] c4 7e [2] df 78 [2] c3 7f [2] df 50 }

  condition:
    any of them
}