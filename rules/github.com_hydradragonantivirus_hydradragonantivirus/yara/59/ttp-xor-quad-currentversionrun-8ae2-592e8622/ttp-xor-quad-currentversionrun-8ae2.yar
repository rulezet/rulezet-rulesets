rule TTP_XOR_QUAD_CurrentVersionRun_8ae2 {
  strings:
    $key_8ae2 = { d9 8d [2] fd 83 [2] d6 af [2] f8 8d [2] ec 96 [2] e3 8c [2] fd 91 [2] ff 90 [2] e4 96 [2] f8 91 [2] e4 be }

  condition:
    any of them
}