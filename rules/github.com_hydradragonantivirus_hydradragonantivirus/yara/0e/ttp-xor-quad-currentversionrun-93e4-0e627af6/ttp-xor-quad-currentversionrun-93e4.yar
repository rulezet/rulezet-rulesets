rule TTP_XOR_QUAD_CurrentVersionRun_93e4 {
  strings:
    $key_93e4 = { c0 8b [2] e4 85 [2] cf a9 [2] e1 8b [2] f5 90 [2] fa 8a [2] e4 97 [2] e6 96 [2] fd 90 [2] e1 97 [2] fd b8 }

  condition:
    any of them
}