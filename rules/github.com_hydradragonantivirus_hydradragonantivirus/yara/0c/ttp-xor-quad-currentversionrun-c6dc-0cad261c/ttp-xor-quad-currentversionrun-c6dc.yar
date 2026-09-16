rule TTP_XOR_QUAD_CurrentVersionRun_c6dc {
  strings:
    $key_c6dc = { 95 b3 [2] b1 bd [2] 9a 91 [2] b4 b3 [2] a0 a8 [2] af b2 [2] b1 af [2] b3 ae [2] a8 a8 [2] b4 af [2] a8 80 }

  condition:
    any of them
}