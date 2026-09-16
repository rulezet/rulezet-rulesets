rule TTP_XOR_QUAD_CurrentVersionRun_a866 {
  strings:
    $key_a866 = { fb 09 [2] df 07 [2] f4 2b [2] da 09 [2] ce 12 [2] c1 08 [2] df 15 [2] dd 14 [2] c6 12 [2] da 15 [2] c6 3a }

  condition:
    any of them
}