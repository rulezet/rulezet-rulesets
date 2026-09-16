rule TTP_XOR_QUAD_CurrentVersionRun_e9cc {
  strings:
    $key_e9cc = { ba a3 [2] 9e ad [2] b5 81 [2] 9b a3 [2] 8f b8 [2] 80 a2 [2] 9e bf [2] 9c be [2] 87 b8 [2] 9b bf [2] 87 90 }

  condition:
    any of them
}