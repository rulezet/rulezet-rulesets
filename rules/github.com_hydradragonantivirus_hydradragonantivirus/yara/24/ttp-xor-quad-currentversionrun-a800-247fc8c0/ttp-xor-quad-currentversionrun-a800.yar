rule TTP_XOR_QUAD_CurrentVersionRun_a800 {
  strings:
    $key_a800 = { fb 6f [2] df 61 [2] f4 4d [2] da 6f [2] ce 74 [2] c1 6e [2] df 73 [2] dd 72 [2] c6 74 [2] da 73 [2] c6 5c }

  condition:
    any of them
}