rule TTP_XOR_QUAD_CurrentVersionRun_8a65 {
  strings:
    $key_8a65 = { d9 0a [2] fd 04 [2] d6 28 [2] f8 0a [2] ec 11 [2] e3 0b [2] fd 16 [2] ff 17 [2] e4 11 [2] f8 16 [2] e4 39 }

  condition:
    any of them
}