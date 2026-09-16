rule TTP_XOR_QUAD_CurrentVersionRun_62cc {
  strings:
    $key_62cc = { 31 a3 [2] 15 ad [2] 3e 81 [2] 10 a3 [2] 04 b8 [2] 0b a2 [2] 15 bf [2] 17 be [2] 0c b8 [2] 10 bf [2] 0c 90 }

  condition:
    any of them
}