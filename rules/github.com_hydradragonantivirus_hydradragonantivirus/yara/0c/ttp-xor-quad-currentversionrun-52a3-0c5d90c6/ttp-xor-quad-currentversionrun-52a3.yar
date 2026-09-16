rule TTP_XOR_QUAD_CurrentVersionRun_52a3 {
  strings:
    $key_52a3 = { 01 cc [2] 25 c2 [2] 0e ee [2] 20 cc [2] 34 d7 [2] 3b cd [2] 25 d0 [2] 27 d1 [2] 3c d7 [2] 20 d0 [2] 3c ff }

  condition:
    any of them
}