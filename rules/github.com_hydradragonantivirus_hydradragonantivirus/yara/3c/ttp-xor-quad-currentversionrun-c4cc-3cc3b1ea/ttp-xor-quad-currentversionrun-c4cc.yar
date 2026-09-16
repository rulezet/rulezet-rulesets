rule TTP_XOR_QUAD_CurrentVersionRun_c4cc {
  strings:
    $key_c4cc = { 97 a3 [2] b3 ad [2] 98 81 [2] b6 a3 [2] a2 b8 [2] ad a2 [2] b3 bf [2] b1 be [2] aa b8 [2] b6 bf [2] aa 90 }

  condition:
    any of them
}