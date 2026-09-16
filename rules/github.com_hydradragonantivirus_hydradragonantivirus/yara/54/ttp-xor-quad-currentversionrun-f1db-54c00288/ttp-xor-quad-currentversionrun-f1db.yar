rule TTP_XOR_QUAD_CurrentVersionRun_f1db {
  strings:
    $key_f1db = { a2 b4 [2] 86 ba [2] ad 96 [2] 83 b4 [2] 97 af [2] 98 b5 [2] 86 a8 [2] 84 a9 [2] 9f af [2] 83 a8 [2] 9f 87 }

  condition:
    any of them
}