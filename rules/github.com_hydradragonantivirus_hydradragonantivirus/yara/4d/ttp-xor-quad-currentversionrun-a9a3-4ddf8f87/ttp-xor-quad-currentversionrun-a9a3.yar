rule TTP_XOR_QUAD_CurrentVersionRun_a9a3 {
  strings:
    $key_a9a3 = { fa cc [2] de c2 [2] f5 ee [2] db cc [2] cf d7 [2] c0 cd [2] de d0 [2] dc d1 [2] c7 d7 [2] db d0 [2] c7 ff }

  condition:
    any of them
}