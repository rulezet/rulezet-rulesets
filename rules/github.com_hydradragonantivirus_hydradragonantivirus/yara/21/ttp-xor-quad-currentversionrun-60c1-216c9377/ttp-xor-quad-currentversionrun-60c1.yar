rule TTP_XOR_QUAD_CurrentVersionRun_60c1 {
  strings:
    $key_60c1 = { 33 ae [2] 17 a0 [2] 3c 8c [2] 12 ae [2] 06 b5 [2] 09 af [2] 17 b2 [2] 15 b3 [2] 0e b5 [2] 12 b2 [2] 0e 9d }

  condition:
    any of them
}