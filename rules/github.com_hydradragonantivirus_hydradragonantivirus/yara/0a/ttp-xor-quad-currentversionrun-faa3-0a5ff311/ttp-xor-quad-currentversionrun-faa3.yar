rule TTP_XOR_QUAD_CurrentVersionRun_faa3 {
  strings:
    $key_faa3 = { a9 cc [2] 8d c2 [2] a6 ee [2] 88 cc [2] 9c d7 [2] 93 cd [2] 8d d0 [2] 8f d1 [2] 94 d7 [2] 88 d0 [2] 94 ff }

  condition:
    any of them
}