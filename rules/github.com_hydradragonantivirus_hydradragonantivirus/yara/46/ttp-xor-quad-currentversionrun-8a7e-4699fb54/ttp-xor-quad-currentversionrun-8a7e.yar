rule TTP_XOR_QUAD_CurrentVersionRun_8a7e {
  strings:
    $key_8a7e = { d9 11 [2] fd 1f [2] d6 33 [2] f8 11 [2] ec 0a [2] e3 10 [2] fd 0d [2] ff 0c [2] e4 0a [2] f8 0d [2] e4 22 }

  condition:
    any of them
}