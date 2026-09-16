rule TTP_XOR_QUAD_CurrentVersionRun_8ae5 {
  strings:
    $key_8ae5 = { d9 8a [2] fd 84 [2] d6 a8 [2] f8 8a [2] ec 91 [2] e3 8b [2] fd 96 [2] ff 97 [2] e4 91 [2] f8 96 [2] e4 b9 }

  condition:
    any of them
}