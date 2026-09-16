rule TTP_XOR_QUAD_CurrentVersionRun_8a1a {
  strings:
    $key_8a1a = { d9 75 [2] fd 7b [2] d6 57 [2] f8 75 [2] ec 6e [2] e3 74 [2] fd 69 [2] ff 68 [2] e4 6e [2] f8 69 [2] e4 46 }

  condition:
    any of them
}