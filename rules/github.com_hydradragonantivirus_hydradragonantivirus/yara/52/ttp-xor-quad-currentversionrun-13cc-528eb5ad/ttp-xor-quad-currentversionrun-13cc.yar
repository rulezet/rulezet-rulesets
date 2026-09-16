rule TTP_XOR_QUAD_CurrentVersionRun_13cc {
  strings:
    $key_13cc = { 40 a3 [2] 64 ad [2] 4f 81 [2] 61 a3 [2] 75 b8 [2] 7a a2 [2] 64 bf [2] 66 be [2] 7d b8 [2] 61 bf [2] 7d 90 }

  condition:
    any of them
}