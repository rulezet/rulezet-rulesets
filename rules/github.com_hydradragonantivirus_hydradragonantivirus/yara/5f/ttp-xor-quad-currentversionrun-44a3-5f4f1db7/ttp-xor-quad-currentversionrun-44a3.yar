rule TTP_XOR_QUAD_CurrentVersionRun_44a3 {
  strings:
    $key_44a3 = { 17 cc [2] 33 c2 [2] 18 ee [2] 36 cc [2] 22 d7 [2] 2d cd [2] 33 d0 [2] 31 d1 [2] 2a d7 [2] 36 d0 [2] 2a ff }

  condition:
    any of them
}