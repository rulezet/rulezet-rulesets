rule TTP_XOR_QUAD_CurrentVersionRun_d1e2 {
  strings:
    $key_d1e2 = { 82 8d [2] a6 83 [2] 8d af [2] a3 8d [2] b7 96 [2] b8 8c [2] a6 91 [2] a4 90 [2] bf 96 [2] a3 91 [2] bf be }

  condition:
    any of them
}