rule TTP_XOR_QUAD_CurrentVersionRun_8a71 {
  strings:
    $key_8a71 = { d9 1e [2] fd 10 [2] d6 3c [2] f8 1e [2] ec 05 [2] e3 1f [2] fd 02 [2] ff 03 [2] e4 05 [2] f8 02 [2] e4 2d }

  condition:
    any of them
}