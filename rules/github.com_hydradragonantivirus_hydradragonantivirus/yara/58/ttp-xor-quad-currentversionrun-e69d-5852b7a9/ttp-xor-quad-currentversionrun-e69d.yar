rule TTP_XOR_QUAD_CurrentVersionRun_e69d {
  strings:
    $key_e69d = { b5 f2 [2] 91 fc [2] ba d0 [2] 94 f2 [2] 80 e9 [2] 8f f3 [2] 91 ee [2] 93 ef [2] 88 e9 [2] 94 ee [2] 88 c1 }

  condition:
    any of them
}