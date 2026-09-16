rule TTP_XOR_QUAD_CurrentVersionRun_8a53 {
  strings:
    $key_8a53 = { d9 3c [2] fd 32 [2] d6 1e [2] f8 3c [2] ec 27 [2] e3 3d [2] fd 20 [2] ff 21 [2] e4 27 [2] f8 20 [2] e4 0f }

  condition:
    any of them
}