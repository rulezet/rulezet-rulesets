rule TTP_XOR_QUAD_CurrentVersionRun_d156 {
  strings:
    $key_d156 = { 82 39 [2] a6 37 [2] 8d 1b [2] a3 39 [2] b7 22 [2] b8 38 [2] a6 25 [2] a4 24 [2] bf 22 [2] a3 25 [2] bf 0a }

  condition:
    any of them
}