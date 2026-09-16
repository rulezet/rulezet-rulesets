rule TTP_XOR_QUAD_CurrentVersionRun_62a3 {
  strings:
    $key_62a3 = { 31 cc [2] 15 c2 [2] 3e ee [2] 10 cc [2] 04 d7 [2] 0b cd [2] 15 d0 [2] 17 d1 [2] 0c d7 [2] 10 d0 [2] 0c ff }

  condition:
    any of them
}