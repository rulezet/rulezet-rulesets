rule TTP_XOR_QUAD_CurrentVersionRun_8a39 {
  strings:
    $key_8a39 = { d9 56 [2] fd 58 [2] d6 74 [2] f8 56 [2] ec 4d [2] e3 57 [2] fd 4a [2] ff 4b [2] e4 4d [2] f8 4a [2] e4 65 }

  condition:
    any of them
}