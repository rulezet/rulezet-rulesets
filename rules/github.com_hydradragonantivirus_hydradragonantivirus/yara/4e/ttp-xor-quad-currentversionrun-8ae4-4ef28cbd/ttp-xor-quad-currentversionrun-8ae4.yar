rule TTP_XOR_QUAD_CurrentVersionRun_8ae4 {
  strings:
    $key_8ae4 = { d9 8b [2] fd 85 [2] d6 a9 [2] f8 8b [2] ec 90 [2] e3 8a [2] fd 97 [2] ff 96 [2] e4 90 [2] f8 97 [2] e4 b8 }

  condition:
    any of them
}