rule TTP_XOR_QUAD_CurrentVersionRun_eba3 {
  strings:
    $key_eba3 = { b8 cc [2] 9c c2 [2] b7 ee [2] 99 cc [2] 8d d7 [2] 82 cd [2] 9c d0 [2] 9e d1 [2] 85 d7 [2] 99 d0 [2] 85 ff }

  condition:
    any of them
}