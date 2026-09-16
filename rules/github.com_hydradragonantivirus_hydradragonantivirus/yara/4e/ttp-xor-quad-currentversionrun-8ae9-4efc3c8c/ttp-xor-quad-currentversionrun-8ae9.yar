rule TTP_XOR_QUAD_CurrentVersionRun_8ae9 {
  strings:
    $key_8ae9 = { d9 86 [2] fd 88 [2] d6 a4 [2] f8 86 [2] ec 9d [2] e3 87 [2] fd 9a [2] ff 9b [2] e4 9d [2] f8 9a [2] e4 b5 }

  condition:
    any of them
}