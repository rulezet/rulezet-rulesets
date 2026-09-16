rule TTP_XOR_QUAD_CurrentVersionRun_c3dc {
  strings:
    $key_c3dc = { 90 b3 [2] b4 bd [2] 9f 91 [2] b1 b3 [2] a5 a8 [2] aa b2 [2] b4 af [2] b6 ae [2] ad a8 [2] b1 af [2] ad 80 }

  condition:
    any of them
}