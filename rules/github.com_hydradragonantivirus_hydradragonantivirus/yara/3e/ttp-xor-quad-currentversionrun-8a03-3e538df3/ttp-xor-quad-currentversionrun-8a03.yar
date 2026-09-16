rule TTP_XOR_QUAD_CurrentVersionRun_8a03 {
  strings:
    $key_8a03 = { d9 6c [2] fd 62 [2] d6 4e [2] f8 6c [2] ec 77 [2] e3 6d [2] fd 70 [2] ff 71 [2] e4 77 [2] f8 70 [2] e4 5f }

  condition:
    any of them
}