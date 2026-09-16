rule TTP_XOR_QUAD_CurrentVersionRun_2edb {
  strings:
    $key_2edb = { 7d b4 [2] 59 ba [2] 72 96 [2] 5c b4 [2] 48 af [2] 47 b5 [2] 59 a8 [2] 5b a9 [2] 40 af [2] 5c a8 [2] 40 87 }

  condition:
    any of them
}