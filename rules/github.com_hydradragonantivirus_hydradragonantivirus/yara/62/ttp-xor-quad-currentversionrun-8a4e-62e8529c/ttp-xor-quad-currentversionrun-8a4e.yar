rule TTP_XOR_QUAD_CurrentVersionRun_8a4e {
  strings:
    $key_8a4e = { d9 21 [2] fd 2f [2] d6 03 [2] f8 21 [2] ec 3a [2] e3 20 [2] fd 3d [2] ff 3c [2] e4 3a [2] f8 3d [2] e4 12 }

  condition:
    any of them
}