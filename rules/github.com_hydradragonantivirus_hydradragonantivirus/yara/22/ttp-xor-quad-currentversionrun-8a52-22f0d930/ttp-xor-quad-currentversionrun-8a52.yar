rule TTP_XOR_QUAD_CurrentVersionRun_8a52 {
  strings:
    $key_8a52 = { d9 3d [2] fd 33 [2] d6 1f [2] f8 3d [2] ec 26 [2] e3 3c [2] fd 21 [2] ff 20 [2] e4 26 [2] f8 21 [2] e4 0e }

  condition:
    any of them
}