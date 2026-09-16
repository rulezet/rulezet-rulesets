rule TTP_XOR_QUAD_CurrentVersionRun_12a3 {
  strings:
    $key_12a3 = { 41 cc [2] 65 c2 [2] 4e ee [2] 60 cc [2] 74 d7 [2] 7b cd [2] 65 d0 [2] 67 d1 [2] 7c d7 [2] 60 d0 [2] 7c ff }

  condition:
    any of them
}