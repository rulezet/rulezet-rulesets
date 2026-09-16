rule TTP_XOR_QUAD_CurrentVersionRun_c881 {
  strings:
    $key_c881 = { 9b ee [2] bf e0 [2] 94 cc [2] ba ee [2] ae f5 [2] a1 ef [2] bf f2 [2] bd f3 [2] a6 f5 [2] ba f2 [2] a6 dd }

  condition:
    any of them
}