rule TTP_XOR_QUAD_CurrentVersionRun_16c0 {
  strings:
    $key_16c0 = { 45 af [2] 61 a1 [2] 4a 8d [2] 64 af [2] 70 b4 [2] 7f ae [2] 61 b3 [2] 63 b2 [2] 78 b4 [2] 64 b3 [2] 78 9c }

  condition:
    any of them
}