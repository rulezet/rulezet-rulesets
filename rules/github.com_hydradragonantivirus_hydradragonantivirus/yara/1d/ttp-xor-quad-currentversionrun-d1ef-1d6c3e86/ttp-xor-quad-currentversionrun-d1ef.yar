rule TTP_XOR_QUAD_CurrentVersionRun_d1ef {
  strings:
    $key_d1ef = { 82 80 [2] a6 8e [2] 8d a2 [2] a3 80 [2] b7 9b [2] b8 81 [2] a6 9c [2] a4 9d [2] bf 9b [2] a3 9c [2] bf b3 }

  condition:
    any of them
}