rule TTP_XOR_QUAD_CurrentVersionRun_16db {
  strings:
    $key_16db = { 45 b4 [2] 61 ba [2] 4a 96 [2] 64 b4 [2] 70 af [2] 7f b5 [2] 61 a8 [2] 63 a9 [2] 78 af [2] 64 a8 [2] 78 87 }

  condition:
    any of them
}