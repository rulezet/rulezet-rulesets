rule TTP_XOR_QUAD_CurrentVersionRun_8a4a {
  strings:
    $key_8a4a = { d9 25 [2] fd 2b [2] d6 07 [2] f8 25 [2] ec 3e [2] e3 24 [2] fd 39 [2] ff 38 [2] e4 3e [2] f8 39 [2] e4 16 }

  condition:
    any of them
}