rule TTP_XOR_QUAD_CurrentVersionRun_dda3 {
  strings:
    $key_dda3 = { 8e cc [2] aa c2 [2] 81 ee [2] af cc [2] bb d7 [2] b4 cd [2] aa d0 [2] a8 d1 [2] b3 d7 [2] af d0 [2] b3 ff }

  condition:
    any of them
}