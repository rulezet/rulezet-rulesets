rule TTP_XOR_QUAD_CurrentVersionRun_20c1 {
  strings:
    $key_20c1 = { 73 ae [2] 57 a0 [2] 7c 8c [2] 52 ae [2] 46 b5 [2] 49 af [2] 57 b2 [2] 55 b3 [2] 4e b5 [2] 52 b2 [2] 4e 9d }

  condition:
    any of them
}