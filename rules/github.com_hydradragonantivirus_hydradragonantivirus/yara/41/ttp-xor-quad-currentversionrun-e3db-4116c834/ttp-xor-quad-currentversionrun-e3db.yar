rule TTP_XOR_QUAD_CurrentVersionRun_e3db {
  strings:
    $key_e3db = { b0 b4 [2] 94 ba [2] bf 96 [2] 91 b4 [2] 85 af [2] 8a b5 [2] 94 a8 [2] 96 a9 [2] 8d af [2] 91 a8 [2] 8d 87 }

  condition:
    any of them
}