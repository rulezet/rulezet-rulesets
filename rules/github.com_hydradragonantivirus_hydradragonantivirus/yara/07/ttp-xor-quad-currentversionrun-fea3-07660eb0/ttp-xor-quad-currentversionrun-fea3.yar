rule TTP_XOR_QUAD_CurrentVersionRun_fea3 {
  strings:
    $key_fea3 = { ad cc [2] 89 c2 [2] a2 ee [2] 8c cc [2] 98 d7 [2] 97 cd [2] 89 d0 [2] 8b d1 [2] 90 d7 [2] 8c d0 [2] 90 ff }

  condition:
    any of them
}