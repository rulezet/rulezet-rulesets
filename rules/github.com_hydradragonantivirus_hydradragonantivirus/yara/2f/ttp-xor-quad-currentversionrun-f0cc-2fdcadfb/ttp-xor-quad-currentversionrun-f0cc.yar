rule TTP_XOR_QUAD_CurrentVersionRun_f0cc {
  strings:
    $key_f0cc = { a3 a3 [2] 87 ad [2] ac 81 [2] 82 a3 [2] 96 b8 [2] 99 a2 [2] 87 bf [2] 85 be [2] 9e b8 [2] 82 bf [2] 9e 90 }

  condition:
    any of them
}