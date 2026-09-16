rule TTP_XOR_QUAD_CurrentVersionRun_a87f {
  strings:
    $key_a87f = { fb 10 [2] df 1e [2] f4 32 [2] da 10 [2] ce 0b [2] c1 11 [2] df 0c [2] dd 0d [2] c6 0b [2] da 0c [2] c6 23 }

  condition:
    any of them
}