rule TTP_XOR_QUAD_CurrentVersionRun_11cc {
  strings:
    $key_11cc = { 42 a3 [2] 66 ad [2] 4d 81 [2] 63 a3 [2] 77 b8 [2] 78 a2 [2] 66 bf [2] 64 be [2] 7f b8 [2] 63 bf [2] 7f 90 }

  condition:
    any of them
}