rule TTP_XOR_QUAD_CurrentVersionRun_a82a {
  strings:
    $key_a82a = { fb 45 [2] df 4b [2] f4 67 [2] da 45 [2] ce 5e [2] c1 44 [2] df 59 [2] dd 58 [2] c6 5e [2] da 59 [2] c6 76 }

  condition:
    any of them
}