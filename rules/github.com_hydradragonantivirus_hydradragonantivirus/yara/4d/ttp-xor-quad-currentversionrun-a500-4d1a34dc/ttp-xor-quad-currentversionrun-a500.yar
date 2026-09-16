rule TTP_XOR_QUAD_CurrentVersionRun_a500 {
  strings:
    $key_a500 = { f6 6f [2] d2 61 [2] f9 4d [2] d7 6f [2] c3 74 [2] cc 6e [2] d2 73 [2] d0 72 [2] cb 74 [2] d7 73 [2] cb 5c }

  condition:
    any of them
}