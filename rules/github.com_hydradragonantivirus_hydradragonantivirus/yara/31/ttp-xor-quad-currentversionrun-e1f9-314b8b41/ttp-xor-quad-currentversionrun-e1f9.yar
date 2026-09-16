rule TTP_XOR_QUAD_CurrentVersionRun_e1f9 {
  strings:
    $key_e1f9 = { b2 96 [2] 96 98 [2] bd b4 [2] 93 96 [2] 87 8d [2] 88 97 [2] 96 8a [2] 94 8b [2] 8f 8d [2] 93 8a [2] 8f a5 }

  condition:
    any of them
}