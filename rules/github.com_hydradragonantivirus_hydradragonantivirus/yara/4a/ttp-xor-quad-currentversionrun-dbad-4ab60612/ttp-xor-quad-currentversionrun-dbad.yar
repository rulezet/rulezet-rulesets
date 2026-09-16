rule TTP_XOR_QUAD_CurrentVersionRun_dbad {
  strings:
    $key_dbad = { 88 c2 [2] ac cc [2] 87 e0 [2] a9 c2 [2] bd d9 [2] b2 c3 [2] ac de [2] ae df [2] b5 d9 [2] a9 de [2] b5 f1 }

  condition:
    any of them
}