rule TTP_XOR_QUAD_CurrentVersionRun_6edb {
  strings:
    $key_6edb = { 3d b4 [2] 19 ba [2] 32 96 [2] 1c b4 [2] 08 af [2] 07 b5 [2] 19 a8 [2] 1b a9 [2] 00 af [2] 1c a8 [2] 00 87 }

  condition:
    any of them
}