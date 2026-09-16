rule TTP_XOR_QUAD_CurrentVersionRun_8a70 {
  strings:
    $key_8a70 = { d9 1f [2] fd 11 [2] d6 3d [2] f8 1f [2] ec 04 [2] e3 1e [2] fd 03 [2] ff 02 [2] e4 04 [2] f8 03 [2] e4 2c }

  condition:
    any of them
}