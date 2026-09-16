rule TTP_XOR_QUAD_CurrentVersionRun_8af9 {
  strings:
    $key_8af9 = { d9 96 [2] fd 98 [2] d6 b4 [2] f8 96 [2] ec 8d [2] e3 97 [2] fd 8a [2] ff 8b [2] e4 8d [2] f8 8a [2] e4 a5 }

  condition:
    any of them
}