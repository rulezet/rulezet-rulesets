rule TTP_XOR_QUAD_CurrentVersionRun_27a3 {
  strings:
    $key_27a3 = { 74 cc [2] 50 c2 [2] 7b ee [2] 55 cc [2] 41 d7 [2] 4e cd [2] 50 d0 [2] 52 d1 [2] 49 d7 [2] 55 d0 [2] 49 ff }

  condition:
    any of them
}