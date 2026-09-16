rule TTP_XOR_QUAD_CurrentVersionRun_d176 {
  strings:
    $key_d176 = { 82 19 [2] a6 17 [2] 8d 3b [2] a3 19 [2] b7 02 [2] b8 18 [2] a6 05 [2] a4 04 [2] bf 02 [2] a3 05 [2] bf 2a }

  condition:
    any of them
}