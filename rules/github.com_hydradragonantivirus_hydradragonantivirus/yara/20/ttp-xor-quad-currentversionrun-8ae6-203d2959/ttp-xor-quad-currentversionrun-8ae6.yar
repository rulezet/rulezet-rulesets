rule TTP_XOR_QUAD_CurrentVersionRun_8ae6 {
  strings:
    $key_8ae6 = { d9 89 [2] fd 87 [2] d6 ab [2] f8 89 [2] ec 92 [2] e3 88 [2] fd 95 [2] ff 94 [2] e4 92 [2] f8 95 [2] e4 ba }

  condition:
    any of them
}