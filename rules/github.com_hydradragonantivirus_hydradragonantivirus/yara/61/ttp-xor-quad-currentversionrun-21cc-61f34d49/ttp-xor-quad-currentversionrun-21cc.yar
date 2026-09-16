rule TTP_XOR_QUAD_CurrentVersionRun_21cc {
  strings:
    $key_21cc = { 72 a3 [2] 56 ad [2] 7d 81 [2] 53 a3 [2] 47 b8 [2] 48 a2 [2] 56 bf [2] 54 be [2] 4f b8 [2] 53 bf [2] 4f 90 }

  condition:
    any of them
}