rule TTP_XOR_QUAD_CurrentVersionRun_8a5e {
  strings:
    $key_8a5e = { d9 31 [2] fd 3f [2] d6 13 [2] f8 31 [2] ec 2a [2] e3 30 [2] fd 2d [2] ff 2c [2] e4 2a [2] f8 2d [2] e4 02 }

  condition:
    any of them
}