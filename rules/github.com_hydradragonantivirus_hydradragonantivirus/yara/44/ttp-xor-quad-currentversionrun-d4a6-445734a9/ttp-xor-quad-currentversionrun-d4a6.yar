rule TTP_XOR_QUAD_CurrentVersionRun_d4a6 {
  strings:
    $key_d4a6 = { 87 c9 [2] a3 c7 [2] 88 eb [2] a6 c9 [2] b2 d2 [2] bd c8 [2] a3 d5 [2] a1 d4 [2] ba d2 [2] a6 d5 [2] ba fa }

  condition:
    any of them
}