rule TTP_XOR_QUAD_CurrentVersionRun_09cc {
  strings:
    $key_09cc = { 5a a3 [2] 7e ad [2] 55 81 [2] 7b a3 [2] 6f b8 [2] 60 a2 [2] 7e bf [2] 7c be [2] 67 b8 [2] 7b bf [2] 67 90 }

  condition:
    any of them
}