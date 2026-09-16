rule TTP_XOR_QUAD_CurrentVersionRun_27cc {
  strings:
    $key_27cc = { 74 a3 [2] 50 ad [2] 7b 81 [2] 55 a3 [2] 41 b8 [2] 4e a2 [2] 50 bf [2] 52 be [2] 49 b8 [2] 55 bf [2] 49 90 }

  condition:
    any of them
}