rule TTP_XOR_QUAD_CurrentVersionRun_1da3 {
  strings:
    $key_1da3 = { 4e cc [2] 6a c2 [2] 41 ee [2] 6f cc [2] 7b d7 [2] 74 cd [2] 6a d0 [2] 68 d1 [2] 73 d7 [2] 6f d0 [2] 73 ff }

  condition:
    any of them
}