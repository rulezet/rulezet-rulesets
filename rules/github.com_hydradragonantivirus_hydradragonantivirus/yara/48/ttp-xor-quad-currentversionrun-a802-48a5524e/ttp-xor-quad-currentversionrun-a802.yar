rule TTP_XOR_QUAD_CurrentVersionRun_a802 {
  strings:
    $key_a802 = { fb 6d [2] df 63 [2] f4 4f [2] da 6d [2] ce 76 [2] c1 6c [2] df 71 [2] dd 70 [2] c6 76 [2] da 71 [2] c6 5e }

  condition:
    any of them
}