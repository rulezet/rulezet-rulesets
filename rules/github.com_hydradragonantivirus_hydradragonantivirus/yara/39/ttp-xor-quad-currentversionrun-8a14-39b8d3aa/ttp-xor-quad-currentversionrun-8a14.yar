rule TTP_XOR_QUAD_CurrentVersionRun_8a14 {
  strings:
    $key_8a14 = { d9 7b [2] fd 75 [2] d6 59 [2] f8 7b [2] ec 60 [2] e3 7a [2] fd 67 [2] ff 66 [2] e4 60 [2] f8 67 [2] e4 48 }

  condition:
    any of them
}