rule TTP_XOR_QUAD_CurrentVersionRun_8a6a {
  strings:
    $key_8a6a = { d9 05 [2] fd 0b [2] d6 27 [2] f8 05 [2] ec 1e [2] e3 04 [2] fd 19 [2] ff 18 [2] e4 1e [2] f8 19 [2] e4 36 }

  condition:
    any of them
}