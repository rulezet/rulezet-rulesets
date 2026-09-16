rule TTP_XOR_QUAD_CurrentVersionRun_a8b3 {
  strings:
    $key_a8b3 = { fb dc [2] df d2 [2] f4 fe [2] da dc [2] ce c7 [2] c1 dd [2] df c0 [2] dd c1 [2] c6 c7 [2] da c0 [2] c6 ef }

  condition:
    any of them
}