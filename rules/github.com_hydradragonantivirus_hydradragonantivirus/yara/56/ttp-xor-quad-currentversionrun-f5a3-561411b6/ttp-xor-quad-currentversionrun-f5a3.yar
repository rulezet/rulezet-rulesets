rule TTP_XOR_QUAD_CurrentVersionRun_f5a3 {
  strings:
    $key_f5a3 = { a6 cc [2] 82 c2 [2] a9 ee [2] 87 cc [2] 93 d7 [2] 9c cd [2] 82 d0 [2] 80 d1 [2] 9b d7 [2] 87 d0 [2] 9b ff }

  condition:
    any of them
}