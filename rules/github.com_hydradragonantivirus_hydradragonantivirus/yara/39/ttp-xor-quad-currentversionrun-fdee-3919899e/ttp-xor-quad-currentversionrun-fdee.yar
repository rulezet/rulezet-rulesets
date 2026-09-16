rule TTP_XOR_QUAD_CurrentVersionRun_fdee {
  strings:
    $key_fdee = { ae 81 [2] 8a 8f [2] a1 a3 [2] 8f 81 [2] 9b 9a [2] 94 80 [2] 8a 9d [2] 88 9c [2] 93 9a [2] 8f 9d [2] 93 b2 }

  condition:
    any of them
}