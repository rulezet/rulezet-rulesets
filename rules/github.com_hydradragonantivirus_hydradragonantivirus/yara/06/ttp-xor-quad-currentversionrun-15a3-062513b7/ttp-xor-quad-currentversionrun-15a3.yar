rule TTP_XOR_QUAD_CurrentVersionRun_15a3 {
  strings:
    $key_15a3 = { 46 cc [2] 62 c2 [2] 49 ee [2] 67 cc [2] 73 d7 [2] 7c cd [2] 62 d0 [2] 60 d1 [2] 7b d7 [2] 67 d0 [2] 7b ff }

  condition:
    any of them
}