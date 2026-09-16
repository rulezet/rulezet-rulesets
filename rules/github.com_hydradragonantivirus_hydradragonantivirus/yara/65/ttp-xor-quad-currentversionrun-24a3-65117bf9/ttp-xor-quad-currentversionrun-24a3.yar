rule TTP_XOR_QUAD_CurrentVersionRun_24a3 {
  strings:
    $key_24a3 = { 77 cc [2] 53 c2 [2] 78 ee [2] 56 cc [2] 42 d7 [2] 4d cd [2] 53 d0 [2] 51 d1 [2] 4a d7 [2] 56 d0 [2] 4a ff }

  condition:
    any of them
}