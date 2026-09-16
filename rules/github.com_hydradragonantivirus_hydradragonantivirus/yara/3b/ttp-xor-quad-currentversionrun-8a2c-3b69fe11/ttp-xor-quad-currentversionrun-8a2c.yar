rule TTP_XOR_QUAD_CurrentVersionRun_8a2c {
  strings:
    $key_8a2c = { d9 43 [2] fd 4d [2] d6 61 [2] f8 43 [2] ec 58 [2] e3 42 [2] fd 5f [2] ff 5e [2] e4 58 [2] f8 5f [2] e4 70 }

  condition:
    any of them
}