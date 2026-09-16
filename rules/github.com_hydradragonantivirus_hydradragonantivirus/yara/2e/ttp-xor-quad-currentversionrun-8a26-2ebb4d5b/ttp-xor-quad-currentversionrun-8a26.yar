rule TTP_XOR_QUAD_CurrentVersionRun_8a26 {
  strings:
    $key_8a26 = { d9 49 [2] fd 47 [2] d6 6b [2] f8 49 [2] ec 52 [2] e3 48 [2] fd 55 [2] ff 54 [2] e4 52 [2] f8 55 [2] e4 7a }

  condition:
    any of them
}