rule TTP_XOR_QUAD_CurrentVersionRun_a87d {
  strings:
    $key_a87d = { fb 12 [2] df 1c [2] f4 30 [2] da 12 [2] ce 09 [2] c1 13 [2] df 0e [2] dd 0f [2] c6 09 [2] da 0e [2] c6 21 }

  condition:
    any of them
}