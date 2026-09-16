rule TTP_XOR_QUAD_CurrentVersionRun_02a3 {
  strings:
    $key_02a3 = { 51 cc [2] 75 c2 [2] 5e ee [2] 70 cc [2] 64 d7 [2] 6b cd [2] 75 d0 [2] 77 d1 [2] 6c d7 [2] 70 d0 [2] 6c ff }

  condition:
    any of them
}