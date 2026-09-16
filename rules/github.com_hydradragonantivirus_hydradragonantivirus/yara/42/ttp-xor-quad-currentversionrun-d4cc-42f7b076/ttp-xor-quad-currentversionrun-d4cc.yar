rule TTP_XOR_QUAD_CurrentVersionRun_d4cc {
  strings:
    $key_d4cc = { 87 a3 [2] a3 ad [2] 88 81 [2] a6 a3 [2] b2 b8 [2] bd a2 [2] a3 bf [2] a1 be [2] ba b8 [2] a6 bf [2] ba 90 }

  condition:
    any of them
}