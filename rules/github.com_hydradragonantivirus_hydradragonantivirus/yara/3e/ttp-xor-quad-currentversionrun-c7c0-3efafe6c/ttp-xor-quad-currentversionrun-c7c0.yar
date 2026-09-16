rule TTP_XOR_QUAD_CurrentVersionRun_c7c0 {
  strings:
    $key_c7c0 = { 94 af [2] b0 a1 [2] 9b 8d [2] b5 af [2] a1 b4 [2] ae ae [2] b0 b3 [2] b2 b2 [2] a9 b4 [2] b5 b3 [2] a9 9c }

  condition:
    any of them
}