rule TTP_XOR_QUAD_CurrentVersionRun_afa3 {
  strings:
    $key_afa3 = { fc cc [2] d8 c2 [2] f3 ee [2] dd cc [2] c9 d7 [2] c6 cd [2] d8 d0 [2] da d1 [2] c1 d7 [2] dd d0 [2] c1 ff }

  condition:
    any of them
}