rule TTP_XOR_QUAD_CurrentVersionRun_8a47 {
  strings:
    $key_8a47 = { d9 28 [2] fd 26 [2] d6 0a [2] f8 28 [2] ec 33 [2] e3 29 [2] fd 34 [2] ff 35 [2] e4 33 [2] f8 34 [2] e4 1b }

  condition:
    any of them
}