rule TTP_XOR_QUAD_CurrentVersionRun_f6db {
  strings:
    $key_f6db = { a5 b4 [2] 81 ba [2] aa 96 [2] 84 b4 [2] 90 af [2] 9f b5 [2] 81 a8 [2] 83 a9 [2] 98 af [2] 84 a8 [2] 98 87 }

  condition:
    any of them
}