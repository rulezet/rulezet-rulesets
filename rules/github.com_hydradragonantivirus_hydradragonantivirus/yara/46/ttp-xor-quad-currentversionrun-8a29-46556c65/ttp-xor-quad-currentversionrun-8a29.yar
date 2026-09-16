rule TTP_XOR_QUAD_CurrentVersionRun_8a29 {
  strings:
    $key_8a29 = { d9 46 [2] fd 48 [2] d6 64 [2] f8 46 [2] ec 5d [2] e3 47 [2] fd 5a [2] ff 5b [2] e4 5d [2] f8 5a [2] e4 75 }

  condition:
    any of them
}