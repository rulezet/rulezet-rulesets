rule TTP_XOR_QUAD_CurrentVersionRun_8af3 {
  strings:
    $key_8af3 = { d9 9c [2] fd 92 [2] d6 be [2] f8 9c [2] ec 87 [2] e3 9d [2] fd 80 [2] ff 81 [2] e4 87 [2] f8 80 [2] e4 af }

  condition:
    any of them
}