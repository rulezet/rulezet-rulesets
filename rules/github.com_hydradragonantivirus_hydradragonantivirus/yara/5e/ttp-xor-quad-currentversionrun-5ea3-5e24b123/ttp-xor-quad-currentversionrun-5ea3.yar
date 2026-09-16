rule TTP_XOR_QUAD_CurrentVersionRun_5ea3 {
  strings:
    $key_5ea3 = { 0d cc [2] 29 c2 [2] 02 ee [2] 2c cc [2] 38 d7 [2] 37 cd [2] 29 d0 [2] 2b d1 [2] 30 d7 [2] 2c d0 [2] 30 ff }

  condition:
    any of them
}