rule TTP_XOR_QUAD_CurrentVersionRun_00c0 {
  strings:
    $key_00c0 = { 53 af [2] 77 a1 [2] 5c 8d [2] 72 af [2] 66 b4 [2] 69 ae [2] 77 b3 [2] 75 b2 [2] 6e b4 [2] 72 b3 [2] 6e 9c }

  condition:
    any of them
}