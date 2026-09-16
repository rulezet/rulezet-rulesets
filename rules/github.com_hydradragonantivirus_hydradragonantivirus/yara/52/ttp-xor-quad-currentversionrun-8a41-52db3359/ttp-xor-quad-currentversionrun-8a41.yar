rule TTP_XOR_QUAD_CurrentVersionRun_8a41 {
  strings:
    $key_8a41 = { d9 2e [2] fd 20 [2] d6 0c [2] f8 2e [2] ec 35 [2] e3 2f [2] fd 32 [2] ff 33 [2] e4 35 [2] f8 32 [2] e4 1d }

  condition:
    any of them
}