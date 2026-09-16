rule TTP_XOR_QUAD_CurrentVersionRun_34a3 {
  strings:
    $key_34a3 = { 67 cc [2] 43 c2 [2] 68 ee [2] 46 cc [2] 52 d7 [2] 5d cd [2] 43 d0 [2] 41 d1 [2] 5a d7 [2] 46 d0 [2] 5a ff }

  condition:
    any of them
}