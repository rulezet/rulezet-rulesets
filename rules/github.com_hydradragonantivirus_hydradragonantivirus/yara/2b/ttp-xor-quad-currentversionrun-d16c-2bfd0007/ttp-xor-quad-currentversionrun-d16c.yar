rule TTP_XOR_QUAD_CurrentVersionRun_d16c {
  strings:
    $key_d16c = { 82 03 [2] a6 0d [2] 8d 21 [2] a3 03 [2] b7 18 [2] b8 02 [2] a6 1f [2] a4 1e [2] bf 18 [2] a3 1f [2] bf 30 }

  condition:
    any of them
}