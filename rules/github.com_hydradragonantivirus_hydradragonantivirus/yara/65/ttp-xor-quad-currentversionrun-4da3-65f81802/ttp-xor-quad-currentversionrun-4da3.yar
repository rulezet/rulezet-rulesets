rule TTP_XOR_QUAD_CurrentVersionRun_4da3 {
  strings:
    $key_4da3 = { 1e cc [2] 3a c2 [2] 11 ee [2] 3f cc [2] 2b d7 [2] 24 cd [2] 3a d0 [2] 38 d1 [2] 23 d7 [2] 3f d0 [2] 23 ff }

  condition:
    any of them
}