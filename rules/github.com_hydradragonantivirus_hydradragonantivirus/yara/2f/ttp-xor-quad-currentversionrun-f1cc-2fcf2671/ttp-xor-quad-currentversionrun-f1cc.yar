rule TTP_XOR_QUAD_CurrentVersionRun_f1cc {
  strings:
    $key_f1cc = { a2 a3 [2] 86 ad [2] ad 81 [2] 83 a3 [2] 97 b8 [2] 98 a2 [2] 86 bf [2] 84 be [2] 9f b8 [2] 83 bf [2] 9f 90 }

  condition:
    any of them
}