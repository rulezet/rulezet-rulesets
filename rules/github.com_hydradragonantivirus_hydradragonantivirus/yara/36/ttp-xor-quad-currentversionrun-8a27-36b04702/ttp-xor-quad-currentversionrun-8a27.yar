rule TTP_XOR_QUAD_CurrentVersionRun_8a27 {
  strings:
    $key_8a27 = { d9 48 [2] fd 46 [2] d6 6a [2] f8 48 [2] ec 53 [2] e3 49 [2] fd 54 [2] ff 55 [2] e4 53 [2] f8 54 [2] e4 7b }

  condition:
    any of them
}