rule TTP_XOR_QUAD_CurrentVersionRun_8a2a {
  strings:
    $key_8a2a = { d9 45 [2] fd 4b [2] d6 67 [2] f8 45 [2] ec 5e [2] e3 44 [2] fd 59 [2] ff 58 [2] e4 5e [2] f8 59 [2] e4 76 }

  condition:
    any of them
}