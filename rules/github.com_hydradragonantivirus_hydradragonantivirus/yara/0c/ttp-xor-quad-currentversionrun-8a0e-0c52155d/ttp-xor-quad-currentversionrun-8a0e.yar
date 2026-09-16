rule TTP_XOR_QUAD_CurrentVersionRun_8a0e {
  strings:
    $key_8a0e = { d9 61 [2] fd 6f [2] d6 43 [2] f8 61 [2] ec 7a [2] e3 60 [2] fd 7d [2] ff 7c [2] e4 7a [2] f8 7d [2] e4 52 }

  condition:
    any of them
}