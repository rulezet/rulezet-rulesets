rule TTP_XOR_QUAD_CurrentVersionRun_a81d {
  strings:
    $key_a81d = { fb 72 [2] df 7c [2] f4 50 [2] da 72 [2] ce 69 [2] c1 73 [2] df 6e [2] dd 6f [2] c6 69 [2] da 6e [2] c6 41 }

  condition:
    any of them
}