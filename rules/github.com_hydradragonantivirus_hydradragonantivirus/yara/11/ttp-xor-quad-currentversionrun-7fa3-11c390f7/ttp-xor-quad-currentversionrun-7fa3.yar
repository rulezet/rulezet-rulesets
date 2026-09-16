rule TTP_XOR_QUAD_CurrentVersionRun_7fa3 {
  strings:
    $key_7fa3 = { 2c cc [2] 08 c2 [2] 23 ee [2] 0d cc [2] 19 d7 [2] 16 cd [2] 08 d0 [2] 0a d1 [2] 11 d7 [2] 0d d0 [2] 11 ff }

  condition:
    any of them
}