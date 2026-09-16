rule TTP_XOR_QUAD_CurrentVersionRun_d1ec {
  strings:
    $key_d1ec = { 82 83 [2] a6 8d [2] 8d a1 [2] a3 83 [2] b7 98 [2] b8 82 [2] a6 9f [2] a4 9e [2] bf 98 [2] a3 9f [2] bf b0 }

  condition:
    any of them
}