rule TTP_XOR_QUAD_CurrentVersionRun_8a77 {
  strings:
    $key_8a77 = { d9 18 [2] fd 16 [2] d6 3a [2] f8 18 [2] ec 03 [2] e3 19 [2] fd 04 [2] ff 05 [2] e4 03 [2] f8 04 [2] e4 2b }

  condition:
    any of them
}