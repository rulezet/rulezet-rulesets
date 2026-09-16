rule TTP_XOR_QUAD_CurrentVersionRun_8a2f {
  strings:
    $key_8a2f = { d9 40 [2] fd 4e [2] d6 62 [2] f8 40 [2] ec 5b [2] e3 41 [2] fd 5c [2] ff 5d [2] e4 5b [2] f8 5c [2] e4 73 }

  condition:
    any of them
}