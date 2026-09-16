rule TTP_XOR_QUAD_CurrentVersionRun_a831 {
  strings:
    $key_a831 = { fb 5e [2] df 50 [2] f4 7c [2] da 5e [2] ce 45 [2] c1 5f [2] df 42 [2] dd 43 [2] c6 45 [2] da 42 [2] c6 6d }

  condition:
    any of them
}