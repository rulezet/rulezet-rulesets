rule TTP_XOR_QUAD_CurrentVersionRun_11c0 {
  strings:
    $key_11c0 = { 42 af [2] 66 a1 [2] 4d 8d [2] 63 af [2] 77 b4 [2] 78 ae [2] 66 b3 [2] 64 b2 [2] 7f b4 [2] 63 b3 [2] 7f 9c }

  condition:
    any of them
}