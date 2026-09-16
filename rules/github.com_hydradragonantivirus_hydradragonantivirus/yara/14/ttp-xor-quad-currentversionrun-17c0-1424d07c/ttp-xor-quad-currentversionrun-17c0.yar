rule TTP_XOR_QUAD_CurrentVersionRun_17c0 {
  strings:
    $key_17c0 = { 44 af [2] 60 a1 [2] 4b 8d [2] 65 af [2] 71 b4 [2] 7e ae [2] 60 b3 [2] 62 b2 [2] 79 b4 [2] 65 b3 [2] 79 9c }

  condition:
    any of them
}