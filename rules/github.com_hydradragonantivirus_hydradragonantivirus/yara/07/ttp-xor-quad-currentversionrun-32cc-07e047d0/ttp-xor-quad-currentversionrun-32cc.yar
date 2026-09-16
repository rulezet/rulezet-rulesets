rule TTP_XOR_QUAD_CurrentVersionRun_32cc {
  strings:
    $key_32cc = { 61 a3 [2] 45 ad [2] 6e 81 [2] 40 a3 [2] 54 b8 [2] 5b a2 [2] 45 bf [2] 47 be [2] 5c b8 [2] 40 bf [2] 5c 90 }

  condition:
    any of them
}