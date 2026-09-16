rule TTP_XOR_QUAD_CurrentVersionRun_c8c0 {
  strings:
    $key_c8c0 = { 9b af [2] bf a1 [2] 94 8d [2] ba af [2] ae b4 [2] a1 ae [2] bf b3 [2] bd b2 [2] a6 b4 [2] ba b3 [2] a6 9c }

  condition:
    any of them
}