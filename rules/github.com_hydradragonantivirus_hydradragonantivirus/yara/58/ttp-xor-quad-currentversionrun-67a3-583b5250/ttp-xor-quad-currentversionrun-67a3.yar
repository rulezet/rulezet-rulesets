rule TTP_XOR_QUAD_CurrentVersionRun_67a3 {
  strings:
    $key_67a3 = { 34 cc [2] 10 c2 [2] 3b ee [2] 15 cc [2] 01 d7 [2] 0e cd [2] 10 d0 [2] 12 d1 [2] 09 d7 [2] 15 d0 [2] 09 ff }

  condition:
    any of them
}