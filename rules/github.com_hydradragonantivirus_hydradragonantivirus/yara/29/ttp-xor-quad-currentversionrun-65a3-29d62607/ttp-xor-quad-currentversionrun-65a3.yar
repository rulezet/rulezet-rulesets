rule TTP_XOR_QUAD_CurrentVersionRun_65a3 {
  strings:
    $key_65a3 = { 36 cc [2] 12 c2 [2] 39 ee [2] 17 cc [2] 03 d7 [2] 0c cd [2] 12 d0 [2] 10 d1 [2] 0b d7 [2] 17 d0 [2] 0b ff }

  condition:
    any of them
}