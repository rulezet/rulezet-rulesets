rule TTP_XOR_QUAD_CurrentVersionRun_e1fa {
  strings:
    $key_e1fa = { b2 95 [2] 96 9b [2] bd b7 [2] 93 95 [2] 87 8e [2] 88 94 [2] 96 89 [2] 94 88 [2] 8f 8e [2] 93 89 [2] 8f a6 }

  condition:
    any of them
}