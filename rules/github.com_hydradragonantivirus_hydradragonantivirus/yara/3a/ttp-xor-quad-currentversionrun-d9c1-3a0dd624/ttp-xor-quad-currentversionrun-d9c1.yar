rule TTP_XOR_QUAD_CurrentVersionRun_d9c1 {
  strings:
    $key_d9c1 = { 8a ae [2] ae a0 [2] 85 8c [2] ab ae [2] bf b5 [2] b0 af [2] ae b2 [2] ac b3 [2] b7 b5 [2] ab b2 [2] b7 9d }

  condition:
    any of them
}