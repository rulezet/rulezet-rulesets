rule TTP_XOR_QUAD_CurrentVersionRun_8a4c {
  strings:
    $key_8a4c = { d9 23 [2] fd 2d [2] d6 01 [2] f8 23 [2] ec 38 [2] e3 22 [2] fd 3f [2] ff 3e [2] e4 38 [2] f8 3f [2] e4 10 }

  condition:
    any of them
}