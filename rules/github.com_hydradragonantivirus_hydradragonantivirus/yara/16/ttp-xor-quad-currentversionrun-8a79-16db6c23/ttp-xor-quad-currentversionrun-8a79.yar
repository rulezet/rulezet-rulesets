rule TTP_XOR_QUAD_CurrentVersionRun_8a79 {
  strings:
    $key_8a79 = { d9 16 [2] fd 18 [2] d6 34 [2] f8 16 [2] ec 0d [2] e3 17 [2] fd 0a [2] ff 0b [2] e4 0d [2] f8 0a [2] e4 25 }

  condition:
    any of them
}