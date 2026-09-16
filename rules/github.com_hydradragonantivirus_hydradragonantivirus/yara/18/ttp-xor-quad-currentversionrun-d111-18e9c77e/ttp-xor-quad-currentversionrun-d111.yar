rule TTP_XOR_QUAD_CurrentVersionRun_d111 {
  strings:
    $key_d111 = { 82 7e [2] a6 70 [2] 8d 5c [2] a3 7e [2] b7 65 [2] b8 7f [2] a6 62 [2] a4 63 [2] bf 65 [2] a3 62 [2] bf 4d }

  condition:
    any of them
}