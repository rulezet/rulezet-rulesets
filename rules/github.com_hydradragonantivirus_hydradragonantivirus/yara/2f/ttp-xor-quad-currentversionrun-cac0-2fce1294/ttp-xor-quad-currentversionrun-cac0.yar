rule TTP_XOR_QUAD_CurrentVersionRun_cac0 {
  strings:
    $key_cac0 = { 99 af [2] bd a1 [2] 96 8d [2] b8 af [2] ac b4 [2] a3 ae [2] bd b3 [2] bf b2 [2] a4 b4 [2] b8 b3 [2] a4 9c }

  condition:
    any of them
}