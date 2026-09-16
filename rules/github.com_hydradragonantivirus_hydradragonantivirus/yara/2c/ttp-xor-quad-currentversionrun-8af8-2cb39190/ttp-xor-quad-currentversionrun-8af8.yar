rule TTP_XOR_QUAD_CurrentVersionRun_8af8 {
  strings:
    $key_8af8 = { d9 97 [2] fd 99 [2] d6 b5 [2] f8 97 [2] ec 8c [2] e3 96 [2] fd 8b [2] ff 8a [2] e4 8c [2] f8 8b [2] e4 a4 }

  condition:
    any of them
}