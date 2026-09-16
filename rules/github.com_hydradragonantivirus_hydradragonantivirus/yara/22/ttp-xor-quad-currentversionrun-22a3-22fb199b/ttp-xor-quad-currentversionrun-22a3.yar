rule TTP_XOR_QUAD_CurrentVersionRun_22a3 {
  strings:
    $key_22a3 = { 71 cc [2] 55 c2 [2] 7e ee [2] 50 cc [2] 44 d7 [2] 4b cd [2] 55 d0 [2] 57 d1 [2] 4c d7 [2] 50 d0 [2] 4c ff }

  condition:
    any of them
}