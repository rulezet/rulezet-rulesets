rule TTP_XOR_QUAD_CurrentVersionRun_a83c {
  strings:
    $key_a83c = { fb 53 [2] df 5d [2] f4 71 [2] da 53 [2] ce 48 [2] c1 52 [2] df 4f [2] dd 4e [2] c6 48 [2] da 4f [2] c6 60 }

  condition:
    any of them
}