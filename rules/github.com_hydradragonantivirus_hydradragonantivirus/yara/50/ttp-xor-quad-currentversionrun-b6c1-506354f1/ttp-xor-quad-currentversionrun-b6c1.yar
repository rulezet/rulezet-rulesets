rule TTP_XOR_QUAD_CurrentVersionRun_b6c1 {
  strings:
    $key_b6c1 = { e5 ae [2] c1 a0 [2] ea 8c [2] c4 ae [2] d0 b5 [2] df af [2] c1 b2 [2] c3 b3 [2] d8 b5 [2] c4 b2 [2] d8 9d }

  condition:
    any of them
}