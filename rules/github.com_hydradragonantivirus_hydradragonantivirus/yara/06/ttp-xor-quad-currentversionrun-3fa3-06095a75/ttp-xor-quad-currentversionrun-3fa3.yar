rule TTP_XOR_QUAD_CurrentVersionRun_3fa3 {
  strings:
    $key_3fa3 = { 6c cc [2] 48 c2 [2] 63 ee [2] 4d cc [2] 59 d7 [2] 56 cd [2] 48 d0 [2] 4a d1 [2] 51 d7 [2] 4d d0 [2] 51 ff }

  condition:
    any of them
}