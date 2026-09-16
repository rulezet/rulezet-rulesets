rule TTP_XOR_QUAD_CurrentVersionRun_8a6c {
  strings:
    $key_8a6c = { d9 03 [2] fd 0d [2] d6 21 [2] f8 03 [2] ec 18 [2] e3 02 [2] fd 1f [2] ff 1e [2] e4 18 [2] f8 1f [2] e4 30 }

  condition:
    any of them
}