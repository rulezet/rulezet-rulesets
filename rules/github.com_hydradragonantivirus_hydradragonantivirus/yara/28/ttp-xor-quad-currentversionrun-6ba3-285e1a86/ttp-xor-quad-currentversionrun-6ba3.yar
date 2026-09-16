rule TTP_XOR_QUAD_CurrentVersionRun_6ba3 {
  strings:
    $key_6ba3 = { 38 cc [2] 1c c2 [2] 37 ee [2] 19 cc [2] 0d d7 [2] 02 cd [2] 1c d0 [2] 1e d1 [2] 05 d7 [2] 19 d0 [2] 05 ff }

  condition:
    any of them
}