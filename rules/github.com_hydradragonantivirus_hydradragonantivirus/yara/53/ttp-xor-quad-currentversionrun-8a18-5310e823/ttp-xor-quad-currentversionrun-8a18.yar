rule TTP_XOR_QUAD_CurrentVersionRun_8a18 {
  strings:
    $key_8a18 = { d9 77 [2] fd 79 [2] d6 55 [2] f8 77 [2] ec 6c [2] e3 76 [2] fd 6b [2] ff 6a [2] e4 6c [2] f8 6b [2] e4 44 }

  condition:
    any of them
}