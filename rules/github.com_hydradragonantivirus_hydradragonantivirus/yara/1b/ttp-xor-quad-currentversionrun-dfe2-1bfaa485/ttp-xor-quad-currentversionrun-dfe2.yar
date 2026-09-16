rule TTP_XOR_QUAD_CurrentVersionRun_dfe2 {
  strings:
    $key_dfe2 = { 8c 8d [2] a8 83 [2] 83 af [2] ad 8d [2] b9 96 [2] b6 8c [2] a8 91 [2] aa 90 [2] b1 96 [2] ad 91 [2] b1 be }

  condition:
    any of them
}