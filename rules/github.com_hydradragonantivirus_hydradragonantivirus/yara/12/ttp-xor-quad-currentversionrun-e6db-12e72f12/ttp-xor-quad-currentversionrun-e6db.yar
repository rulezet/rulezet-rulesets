rule TTP_XOR_QUAD_CurrentVersionRun_e6db {
  strings:
    $key_e6db = { b5 b4 [2] 91 ba [2] ba 96 [2] 94 b4 [2] 80 af [2] 8f b5 [2] 91 a8 [2] 93 a9 [2] 88 af [2] 94 a8 [2] 88 87 }

  condition:
    any of them
}