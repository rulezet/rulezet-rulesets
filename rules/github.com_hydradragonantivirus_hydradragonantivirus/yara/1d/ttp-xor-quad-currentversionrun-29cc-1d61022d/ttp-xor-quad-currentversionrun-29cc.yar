rule TTP_XOR_QUAD_CurrentVersionRun_29cc {
  strings:
    $key_29cc = { 7a a3 [2] 5e ad [2] 75 81 [2] 5b a3 [2] 4f b8 [2] 40 a2 [2] 5e bf [2] 5c be [2] 47 b8 [2] 5b bf [2] 47 90 }

  condition:
    any of them
}