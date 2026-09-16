rule TTP_XOR_QUAD_CurrentVersionRun_f4cc {
  strings:
    $key_f4cc = { a7 a3 [2] 83 ad [2] a8 81 [2] 86 a3 [2] 92 b8 [2] 9d a2 [2] 83 bf [2] 81 be [2] 9a b8 [2] 86 bf [2] 9a 90 }

  condition:
    any of them
}