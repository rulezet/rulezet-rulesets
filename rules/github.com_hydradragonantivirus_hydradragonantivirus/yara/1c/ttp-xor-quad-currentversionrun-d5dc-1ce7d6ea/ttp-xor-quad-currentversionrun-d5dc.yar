rule TTP_XOR_QUAD_CurrentVersionRun_d5dc {
  strings:
    $key_d5dc = { 86 b3 [2] a2 bd [2] 89 91 [2] a7 b3 [2] b3 a8 [2] bc b2 [2] a2 af [2] a0 ae [2] bb a8 [2] a7 af [2] bb 80 }

  condition:
    any of them
}