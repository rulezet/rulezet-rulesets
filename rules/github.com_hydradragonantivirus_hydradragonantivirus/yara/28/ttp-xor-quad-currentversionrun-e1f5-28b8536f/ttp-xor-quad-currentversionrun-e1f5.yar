rule TTP_XOR_QUAD_CurrentVersionRun_e1f5 {
  strings:
    $key_e1f5 = { b2 9a [2] 96 94 [2] bd b8 [2] 93 9a [2] 87 81 [2] 88 9b [2] 96 86 [2] 94 87 [2] 8f 81 [2] 93 86 [2] 8f a9 }

  condition:
    any of them
}