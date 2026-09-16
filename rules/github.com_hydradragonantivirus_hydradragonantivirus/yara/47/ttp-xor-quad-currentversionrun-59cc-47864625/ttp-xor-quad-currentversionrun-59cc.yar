rule TTP_XOR_QUAD_CurrentVersionRun_59cc {
  strings:
    $key_59cc = { 0a a3 [2] 2e ad [2] 05 81 [2] 2b a3 [2] 3f b8 [2] 30 a2 [2] 2e bf [2] 2c be [2] 37 b8 [2] 2b bf [2] 37 90 }

  condition:
    any of them
}