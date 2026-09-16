rule TTP_XOR_QUAD_CurrentVersionRun_a8b1 {
  strings:
    $key_a8b1 = { fb de [2] df d0 [2] f4 fc [2] da de [2] ce c5 [2] c1 df [2] df c2 [2] dd c3 [2] c6 c5 [2] da c2 [2] c6 ed }

  condition:
    any of them
}