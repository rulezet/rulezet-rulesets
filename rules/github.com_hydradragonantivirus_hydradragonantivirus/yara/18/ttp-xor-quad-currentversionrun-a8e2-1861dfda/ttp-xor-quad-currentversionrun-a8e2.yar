rule TTP_XOR_QUAD_CurrentVersionRun_a8e2 {
  strings:
    $key_a8e2 = { fb 8d [2] df 83 [2] f4 af [2] da 8d [2] ce 96 [2] c1 8c [2] df 91 [2] dd 90 [2] c6 96 [2] da 91 [2] c6 be }

  condition:
    any of them
}