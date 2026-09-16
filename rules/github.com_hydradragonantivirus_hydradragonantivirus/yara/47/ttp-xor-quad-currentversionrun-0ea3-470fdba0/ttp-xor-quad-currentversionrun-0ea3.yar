rule TTP_XOR_QUAD_CurrentVersionRun_0ea3 {
  strings:
    $key_0ea3 = { 5d cc [2] 79 c2 [2] 52 ee [2] 7c cc [2] 68 d7 [2] 67 cd [2] 79 d0 [2] 7b d1 [2] 60 d7 [2] 7c d0 [2] 60 ff }

  condition:
    any of them
}