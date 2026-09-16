rule TTP_XOR_QUAD_CurrentVersionRun_1aa3 {
  strings:
    $key_1aa3 = { 49 cc [2] 6d c2 [2] 46 ee [2] 68 cc [2] 7c d7 [2] 73 cd [2] 6d d0 [2] 6f d1 [2] 74 d7 [2] 68 d0 [2] 74 ff }

  condition:
    any of them
}