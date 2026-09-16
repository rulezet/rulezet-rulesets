rule TTP_XOR_QUAD_CurrentVersionRun_a87c {
  strings:
    $key_a87c = { fb 13 [2] df 1d [2] f4 31 [2] da 13 [2] ce 08 [2] c1 12 [2] df 0f [2] dd 0e [2] c6 08 [2] da 0f [2] c6 20 }

  condition:
    any of them
}