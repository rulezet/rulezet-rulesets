rule TTP_XOR_QUAD_CurrentVersionRun_d1fc {
  strings:
    $key_d1fc = { 82 93 [2] a6 9d [2] 8d b1 [2] a3 93 [2] b7 88 [2] b8 92 [2] a6 8f [2] a4 8e [2] bf 88 [2] a3 8f [2] bf a0 }

  condition:
    any of them
}