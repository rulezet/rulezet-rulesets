rule TTP_XOR_QUAD_CurrentVersionRun_75a3 {
  strings:
    $key_75a3 = { 26 cc [2] 02 c2 [2] 29 ee [2] 07 cc [2] 13 d7 [2] 1c cd [2] 02 d0 [2] 00 d1 [2] 1b d7 [2] 07 d0 [2] 1b ff }

  condition:
    any of them
}