rule TTP_XOR_QUAD_CurrentVersionRun_40c0 {
  strings:
    $key_40c0 = { 13 af [2] 37 a1 [2] 1c 8d [2] 32 af [2] 26 b4 [2] 29 ae [2] 37 b3 [2] 35 b2 [2] 2e b4 [2] 32 b3 [2] 2e 9c }

  condition:
    any of them
}