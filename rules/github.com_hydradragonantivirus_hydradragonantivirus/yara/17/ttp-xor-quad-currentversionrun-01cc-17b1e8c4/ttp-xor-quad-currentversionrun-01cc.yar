rule TTP_XOR_QUAD_CurrentVersionRun_01cc {
  strings:
    $key_01cc = { 52 a3 [2] 76 ad [2] 5d 81 [2] 73 a3 [2] 67 b8 [2] 68 a2 [2] 76 bf [2] 74 be [2] 6f b8 [2] 73 bf [2] 6f 90 }

  condition:
    any of them
}