rule TTP_XOR_QUAD_CurrentVersionRun_8af7 {
  strings:
    $key_8af7 = { d9 98 [2] fd 96 [2] d6 ba [2] f8 98 [2] ec 83 [2] e3 99 [2] fd 84 [2] ff 85 [2] e4 83 [2] f8 84 [2] e4 ab }

  condition:
    any of them
}