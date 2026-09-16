rule TTP_XOR_QUAD_CurrentVersionRun_d6cc {
  strings:
    $key_d6cc = { 85 a3 [2] a1 ad [2] 8a 81 [2] a4 a3 [2] b0 b8 [2] bf a2 [2] a1 bf [2] a3 be [2] b8 b8 [2] a4 bf [2] b8 90 }

  condition:
    any of them
}