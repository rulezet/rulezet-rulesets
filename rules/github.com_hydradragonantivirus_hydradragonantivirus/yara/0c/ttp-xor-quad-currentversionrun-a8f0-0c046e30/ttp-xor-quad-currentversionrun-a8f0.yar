rule TTP_XOR_QUAD_CurrentVersionRun_a8f0 {
  strings:
    $key_a8f0 = { fb 9f [2] df 91 [2] f4 bd [2] da 9f [2] ce 84 [2] c1 9e [2] df 83 [2] dd 82 [2] c6 84 [2] da 83 [2] c6 ac }

  condition:
    any of them
}