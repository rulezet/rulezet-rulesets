rule TTP_XOR_QUAD_CurrentVersionRun_8a48 {
  strings:
    $key_8a48 = { d9 27 [2] fd 29 [2] d6 05 [2] f8 27 [2] ec 3c [2] e3 26 [2] fd 3b [2] ff 3a [2] e4 3c [2] f8 3b [2] e4 14 }

  condition:
    any of them
}