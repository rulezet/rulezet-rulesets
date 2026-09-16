rule TTP_XOR_QUAD_CurrentVersionRun_8a64 {
  strings:
    $key_8a64 = { d9 0b [2] fd 05 [2] d6 29 [2] f8 0b [2] ec 10 [2] e3 0a [2] fd 17 [2] ff 16 [2] e4 10 [2] f8 17 [2] e4 38 }

  condition:
    any of them
}