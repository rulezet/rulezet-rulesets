rule TTP_XOR_QUAD_CurrentVersionRun_a81c {
  strings:
    $key_a81c = { fb 73 [2] df 7d [2] f4 51 [2] da 73 [2] ce 68 [2] c1 72 [2] df 6f [2] dd 6e [2] c6 68 [2] da 6f [2] c6 40 }

  condition:
    any of them
}