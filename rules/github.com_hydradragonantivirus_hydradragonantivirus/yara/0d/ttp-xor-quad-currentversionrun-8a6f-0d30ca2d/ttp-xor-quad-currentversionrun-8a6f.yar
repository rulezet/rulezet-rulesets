rule TTP_XOR_QUAD_CurrentVersionRun_8a6f {
  strings:
    $key_8a6f = { d9 00 [2] fd 0e [2] d6 22 [2] f8 00 [2] ec 1b [2] e3 01 [2] fd 1c [2] ff 1d [2] e4 1b [2] f8 1c [2] e4 33 }

  condition:
    any of them
}