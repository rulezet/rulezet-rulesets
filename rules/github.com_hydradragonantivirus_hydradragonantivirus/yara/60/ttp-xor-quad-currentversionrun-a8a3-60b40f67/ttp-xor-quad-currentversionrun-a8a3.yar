rule TTP_XOR_QUAD_CurrentVersionRun_a8a3 {
  strings:
    $key_a8a3 = { fb cc [2] df c2 [2] f4 ee [2] da cc [2] ce d7 [2] c1 cd [2] df d0 [2] dd d1 [2] c6 d7 [2] da d0 [2] c6 ff }

  condition:
    any of them
}