rule TTP_XOR_QUAD_CurrentVersionRun_c3c1 {
  strings:
    $key_c3c1 = { 90 ae [2] b4 a0 [2] 9f 8c [2] b1 ae [2] a5 b5 [2] aa af [2] b4 b2 [2] b6 b3 [2] ad b5 [2] b1 b2 [2] ad 9d }

  condition:
    any of them
}