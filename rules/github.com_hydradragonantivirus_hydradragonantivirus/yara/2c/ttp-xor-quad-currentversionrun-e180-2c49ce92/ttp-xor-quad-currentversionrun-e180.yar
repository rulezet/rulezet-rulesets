rule TTP_XOR_QUAD_CurrentVersionRun_e180 {
  strings:
    $key_e180 = { b2 ef [2] 96 e1 [2] bd cd [2] 93 ef [2] 87 f4 [2] 88 ee [2] 96 f3 [2] 94 f2 [2] 8f f4 [2] 93 f3 [2] 8f dc }

  condition:
    any of them
}