rule TTP_XOR_QUAD_CurrentVersionRun_d5c1 {
  strings:
    $key_d5c1 = { 86 ae [2] a2 a0 [2] 89 8c [2] a7 ae [2] b3 b5 [2] bc af [2] a2 b2 [2] a0 b3 [2] bb b5 [2] a7 b2 [2] bb 9d }

  condition:
    any of them
}