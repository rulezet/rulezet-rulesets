rule TTP_XOR_QUAD_CurrentVersionRun_d7cc {
  strings:
    $key_d7cc = { 84 a3 [2] a0 ad [2] 8b 81 [2] a5 a3 [2] b1 b8 [2] be a2 [2] a0 bf [2] a2 be [2] b9 b8 [2] a5 bf [2] b9 90 }

  condition:
    any of them
}