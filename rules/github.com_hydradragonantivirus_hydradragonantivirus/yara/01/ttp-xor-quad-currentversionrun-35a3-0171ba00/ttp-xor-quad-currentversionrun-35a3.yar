rule TTP_XOR_QUAD_CurrentVersionRun_35a3 {
  strings:
    $key_35a3 = { 66 cc [2] 42 c2 [2] 69 ee [2] 47 cc [2] 53 d7 [2] 5c cd [2] 42 d0 [2] 40 d1 [2] 5b d7 [2] 47 d0 [2] 5b ff }

  condition:
    any of them
}