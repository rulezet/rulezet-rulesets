rule TTP_XOR_QUAD_CurrentVersionRun_54a3 {
  strings:
    $key_54a3 = { 07 cc [2] 23 c2 [2] 08 ee [2] 26 cc [2] 32 d7 [2] 3d cd [2] 23 d0 [2] 21 d1 [2] 3a d7 [2] 26 d0 [2] 3a ff }

  condition:
    any of them
}