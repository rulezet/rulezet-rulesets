rule TTP_XOR_QUAD_CurrentVersionRun_10c0 {
  strings:
    $key_10c0 = { 43 af [2] 67 a1 [2] 4c 8d [2] 62 af [2] 76 b4 [2] 79 ae [2] 67 b3 [2] 65 b2 [2] 7e b4 [2] 62 b3 [2] 7e 9c }

  condition:
    any of them
}