rule TTP_XOR_QUAD_CurrentVersionRun_8a67 {
  strings:
    $key_8a67 = { d9 08 [2] fd 06 [2] d6 2a [2] f8 08 [2] ec 13 [2] e3 09 [2] fd 14 [2] ff 15 [2] e4 13 [2] f8 14 [2] e4 3b }

  condition:
    any of them
}