rule TTP_XOR_QUAD_CurrentVersionRun_a86a {
  strings:
    $key_a86a = { fb 05 [2] df 0b [2] f4 27 [2] da 05 [2] ce 1e [2] c1 04 [2] df 19 [2] dd 18 [2] c6 1e [2] da 19 [2] c6 36 }

  condition:
    any of them
}