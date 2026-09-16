rule TTP_XOR_QUAD_CurrentVersionRun_f180 {
  strings:
    $key_f180 = { a2 ef [2] 86 e1 [2] ad cd [2] 83 ef [2] 97 f4 [2] 98 ee [2] 86 f3 [2] 84 f2 [2] 9f f4 [2] 83 f3 [2] 9f dc }

  condition:
    any of them
}