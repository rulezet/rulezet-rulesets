rule TTP_XOR_QUAD_CurrentVersionRun_11c1 {
  strings:
    $key_11c1 = { 42 ae [2] 66 a0 [2] 4d 8c [2] 63 ae [2] 77 b5 [2] 78 af [2] 66 b2 [2] 64 b3 [2] 7f b5 [2] 63 b2 [2] 7f 9d }

  condition:
    any of them
}