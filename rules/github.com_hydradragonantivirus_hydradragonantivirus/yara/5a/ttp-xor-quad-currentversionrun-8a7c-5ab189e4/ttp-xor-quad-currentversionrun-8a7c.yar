rule TTP_XOR_QUAD_CurrentVersionRun_8a7c {
  strings:
    $key_8a7c = { d9 13 [2] fd 1d [2] d6 31 [2] f8 13 [2] ec 08 [2] e3 12 [2] fd 0f [2] ff 0e [2] e4 08 [2] f8 0f [2] e4 20 }

  condition:
    any of them
}