rule TTP_XOR_QUAD_CurrentVersionRun_8a36 {
  strings:
    $key_8a36 = { d9 59 [2] fd 57 [2] d6 7b [2] f8 59 [2] ec 42 [2] e3 58 [2] fd 45 [2] ff 44 [2] e4 42 [2] f8 45 [2] e4 6a }

  condition:
    any of them
}