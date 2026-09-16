rule TTP_XOR_QUAD_CurrentVersionRun_77a3 {
  strings:
    $key_77a3 = { 24 cc [2] 00 c2 [2] 2b ee [2] 05 cc [2] 11 d7 [2] 1e cd [2] 00 d0 [2] 02 d1 [2] 19 d7 [2] 05 d0 [2] 19 ff }

  condition:
    any of them
}