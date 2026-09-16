rule TTP_XOR_QUAD_CurrentVersionRun_8a58 {
  strings:
    $key_8a58 = { d9 37 [2] fd 39 [2] d6 15 [2] f8 37 [2] ec 2c [2] e3 36 [2] fd 2b [2] ff 2a [2] e4 2c [2] f8 2b [2] e4 04 }

  condition:
    any of them
}