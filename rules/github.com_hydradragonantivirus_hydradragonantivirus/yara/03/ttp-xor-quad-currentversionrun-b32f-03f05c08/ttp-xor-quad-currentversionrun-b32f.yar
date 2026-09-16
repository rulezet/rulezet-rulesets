rule TTP_XOR_QUAD_CurrentVersionRun_b32f {
  strings:
    $key_b32f = { e0 40 [2] c4 4e [2] ef 62 [2] c1 40 [2] d5 5b [2] da 41 [2] c4 5c [2] c6 5d [2] dd 5b [2] c1 5c [2] dd 73 }

  condition:
    any of them
}