rule TTP_XOR_QUAD_CurrentVersionRun_06a3 {
  strings:
    $key_06a3 = { 55 cc [2] 71 c2 [2] 5a ee [2] 74 cc [2] 60 d7 [2] 6f cd [2] 71 d0 [2] 73 d1 [2] 68 d7 [2] 74 d0 [2] 68 ff }

  condition:
    any of them
}