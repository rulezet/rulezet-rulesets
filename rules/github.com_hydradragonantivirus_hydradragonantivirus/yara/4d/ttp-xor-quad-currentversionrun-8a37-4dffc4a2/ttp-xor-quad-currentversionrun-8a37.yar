rule TTP_XOR_QUAD_CurrentVersionRun_8a37 {
  strings:
    $key_8a37 = { d9 58 [2] fd 56 [2] d6 7a [2] f8 58 [2] ec 43 [2] e3 59 [2] fd 44 [2] ff 45 [2] e4 43 [2] f8 44 [2] e4 6b }

  condition:
    any of them
}