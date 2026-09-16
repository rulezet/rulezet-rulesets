rule TTP_XOR_QUAD_CurrentVersionRun_e5db {
  strings:
    $key_e5db = { b6 b4 [2] 92 ba [2] b9 96 [2] 97 b4 [2] 83 af [2] 8c b5 [2] 92 a8 [2] 90 a9 [2] 8b af [2] 97 a8 [2] 8b 87 }

  condition:
    any of them
}