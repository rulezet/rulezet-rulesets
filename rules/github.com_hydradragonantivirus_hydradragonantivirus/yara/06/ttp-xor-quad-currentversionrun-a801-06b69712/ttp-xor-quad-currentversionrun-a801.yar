rule TTP_XOR_QUAD_CurrentVersionRun_a801 {
  strings:
    $key_a801 = { fb 6e [2] df 60 [2] f4 4c [2] da 6e [2] ce 75 [2] c1 6f [2] df 72 [2] dd 73 [2] c6 75 [2] da 72 [2] c6 5d }

  condition:
    any of them
}