rule TTP_XOR_QUAD_CurrentVersionRun_6fa3 {
  strings:
    $key_6fa3 = { 3c cc [2] 18 c2 [2] 33 ee [2] 1d cc [2] 09 d7 [2] 06 cd [2] 18 d0 [2] 1a d1 [2] 01 d7 [2] 1d d0 [2] 01 ff }

  condition:
    any of them
}