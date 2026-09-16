rule TTP_XOR_QUAD_CurrentVersionRun_93e5 {
  strings:
    $key_93e5 = { c0 8a [2] e4 84 [2] cf a8 [2] e1 8a [2] f5 91 [2] fa 8b [2] e4 96 [2] e6 97 [2] fd 91 [2] e1 96 [2] fd b9 }

  condition:
    any of them
}