rule TTP_XOR_QUAD_CurrentVersionRun_8a69 {
  strings:
    $key_8a69 = { d9 06 [2] fd 08 [2] d6 24 [2] f8 06 [2] ec 1d [2] e3 07 [2] fd 1a [2] ff 1b [2] e4 1d [2] f8 1a [2] e4 35 }

  condition:
    any of them
}