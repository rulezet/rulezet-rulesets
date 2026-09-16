rule TTP_XOR_QUAD_CurrentVersionRun_d13a {
  strings:
    $key_d13a = { 82 55 [2] a6 5b [2] 8d 77 [2] a3 55 [2] b7 4e [2] b8 54 [2] a6 49 [2] a4 48 [2] bf 4e [2] a3 49 [2] bf 66 }

  condition:
    any of them
}