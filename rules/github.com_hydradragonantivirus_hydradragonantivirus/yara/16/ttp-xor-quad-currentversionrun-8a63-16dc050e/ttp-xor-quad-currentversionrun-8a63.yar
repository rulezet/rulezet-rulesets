rule TTP_XOR_QUAD_CurrentVersionRun_8a63 {
  strings:
    $key_8a63 = { d9 0c [2] fd 02 [2] d6 2e [2] f8 0c [2] ec 17 [2] e3 0d [2] fd 10 [2] ff 11 [2] e4 17 [2] f8 10 [2] e4 3f }

  condition:
    any of them
}