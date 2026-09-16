rule TTP_XOR_QUAD_CurrentVersionRun_64a3 {
  strings:
    $key_64a3 = { 37 cc [2] 13 c2 [2] 38 ee [2] 16 cc [2] 02 d7 [2] 0d cd [2] 13 d0 [2] 11 d1 [2] 0a d7 [2] 16 d0 [2] 0a ff }

  condition:
    any of them
}