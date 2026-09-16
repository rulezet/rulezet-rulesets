rule TTP_XOR_QUAD_CurrentVersionRun_07a3 {
  strings:
    $key_07a3 = { 54 cc [2] 70 c2 [2] 5b ee [2] 75 cc [2] 61 d7 [2] 6e cd [2] 70 d0 [2] 72 d1 [2] 69 d7 [2] 75 d0 [2] 69 ff }

  condition:
    any of them
}