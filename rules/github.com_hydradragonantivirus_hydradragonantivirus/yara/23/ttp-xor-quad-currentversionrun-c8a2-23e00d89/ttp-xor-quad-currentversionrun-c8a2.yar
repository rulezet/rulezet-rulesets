rule TTP_XOR_QUAD_CurrentVersionRun_c8a2 {
  strings:
    $key_c8a2 = { 9b cd [2] bf c3 [2] 94 ef [2] ba cd [2] ae d6 [2] a1 cc [2] bf d1 [2] bd d0 [2] a6 d6 [2] ba d1 [2] a6 fe }

  condition:
    any of them
}