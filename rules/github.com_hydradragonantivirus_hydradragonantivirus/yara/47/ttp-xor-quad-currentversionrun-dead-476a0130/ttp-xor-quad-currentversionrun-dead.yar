rule TTP_XOR_QUAD_CurrentVersionRun_dead {
  strings:
    $key_dead = { 8d c2 [2] a9 cc [2] 82 e0 [2] ac c2 [2] b8 d9 [2] b7 c3 [2] a9 de [2] ab df [2] b0 d9 [2] ac de [2] b0 f1 }

  condition:
    any of them
}