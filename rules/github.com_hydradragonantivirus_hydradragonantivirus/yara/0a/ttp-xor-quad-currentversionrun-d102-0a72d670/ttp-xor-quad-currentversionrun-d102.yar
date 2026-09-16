rule TTP_XOR_QUAD_CurrentVersionRun_d102 {
  strings:
    $key_d102 = { 82 6d [2] a6 63 [2] 8d 4f [2] a3 6d [2] b7 76 [2] b8 6c [2] a6 71 [2] a4 70 [2] bf 76 [2] a3 71 [2] bf 5e }

  condition:
    any of them
}