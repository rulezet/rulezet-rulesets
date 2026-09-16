rule TTP_XOR_QUAD_CurrentVersionRun_cec0 {
  strings:
    $key_cec0 = { 9d af [2] b9 a1 [2] 92 8d [2] bc af [2] a8 b4 [2] a7 ae [2] b9 b3 [2] bb b2 [2] a0 b4 [2] bc b3 [2] a0 9c }

  condition:
    any of them
}