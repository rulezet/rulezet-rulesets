rule TTP_XOR_QUAD_CurrentVersionRun_5786 {
  strings:
    $key_5786 = { 04 e9 [2] 20 e7 [2] 0b cb [2] 25 e9 [2] 31 f2 [2] 3e e8 [2] 20 f5 [2] 22 f4 [2] 39 f2 [2] 25 f5 [2] 39 da }

  condition:
    any of them
}