rule TTP_XOR_QUAD_CurrentVersionRun_71cc {
  strings:
    $key_71cc = { 22 a3 [2] 06 ad [2] 2d 81 [2] 03 a3 [2] 17 b8 [2] 18 a2 [2] 06 bf [2] 04 be [2] 1f b8 [2] 03 bf [2] 1f 90 }

  condition:
    any of them
}