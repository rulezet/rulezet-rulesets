rule TTP_XOR_QUAD_CurrentVersionRun_10c1 {
  strings:
    $key_10c1 = { 43 ae [2] 67 a0 [2] 4c 8c [2] 62 ae [2] 76 b5 [2] 79 af [2] 67 b2 [2] 65 b3 [2] 7e b5 [2] 62 b2 [2] 7e 9d }

  condition:
    any of them
}