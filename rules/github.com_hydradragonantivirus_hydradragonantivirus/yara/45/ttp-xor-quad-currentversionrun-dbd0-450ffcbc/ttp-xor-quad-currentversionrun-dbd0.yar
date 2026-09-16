rule TTP_XOR_QUAD_CurrentVersionRun_dbd0 {
  strings:
    $key_dbd0 = { 88 bf [2] ac b1 [2] 87 9d [2] a9 bf [2] bd a4 [2] b2 be [2] ac a3 [2] ae a2 [2] b5 a4 [2] a9 a3 [2] b5 8c }

  condition:
    any of them
}