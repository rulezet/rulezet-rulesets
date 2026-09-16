rule TTP_XOR_QUAD_CurrentVersionRun_ffa3 {
  strings:
    $key_ffa3 = { ac cc [2] 88 c2 [2] a3 ee [2] 8d cc [2] 99 d7 [2] 96 cd [2] 88 d0 [2] 8a d1 [2] 91 d7 [2] 8d d0 [2] 91 ff }

  condition:
    any of them
}