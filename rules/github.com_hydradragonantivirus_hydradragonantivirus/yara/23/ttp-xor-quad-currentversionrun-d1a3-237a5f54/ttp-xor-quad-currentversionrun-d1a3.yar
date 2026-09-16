rule TTP_XOR_QUAD_CurrentVersionRun_d1a3 {
  strings:
    $key_d1a3 = { 82 cc [2] a6 c2 [2] 8d ee [2] a3 cc [2] b7 d7 [2] b8 cd [2] a6 d0 [2] a4 d1 [2] bf d7 [2] a3 d0 [2] bf ff }

  condition:
    any of them
}