rule TTP_XOR_QUAD_CurrentVersionRun_d134 {
  strings:
    $key_d134 = { 82 5b [2] a6 55 [2] 8d 79 [2] a3 5b [2] b7 40 [2] b8 5a [2] a6 47 [2] a4 46 [2] bf 40 [2] a3 47 [2] bf 68 }

  condition:
    any of them
}