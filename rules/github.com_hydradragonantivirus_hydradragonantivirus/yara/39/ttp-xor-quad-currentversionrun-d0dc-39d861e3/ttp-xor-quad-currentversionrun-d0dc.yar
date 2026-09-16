rule TTP_XOR_QUAD_CurrentVersionRun_d0dc {
  strings:
    $key_d0dc = { 83 b3 [2] a7 bd [2] 8c 91 [2] a2 b3 [2] b6 a8 [2] b9 b2 [2] a7 af [2] a5 ae [2] be a8 [2] a2 af [2] be 80 }

  condition:
    any of them
}