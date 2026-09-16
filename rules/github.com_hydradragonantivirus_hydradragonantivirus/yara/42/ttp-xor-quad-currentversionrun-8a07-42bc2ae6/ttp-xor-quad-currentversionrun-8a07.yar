rule TTP_XOR_QUAD_CurrentVersionRun_8a07 {
  strings:
    $key_8a07 = { d9 68 [2] fd 66 [2] d6 4a [2] f8 68 [2] ec 73 [2] e3 69 [2] fd 74 [2] ff 75 [2] e4 73 [2] f8 74 [2] e4 5b }

  condition:
    any of them
}