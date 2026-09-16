rule TTP_XOR_QUAD_CurrentVersionRun_f7cc {
  strings:
    $key_f7cc = { a4 a3 [2] 80 ad [2] ab 81 [2] 85 a3 [2] 91 b8 [2] 9e a2 [2] 80 bf [2] 82 be [2] 99 b8 [2] 85 bf [2] 99 90 }

  condition:
    any of them
}