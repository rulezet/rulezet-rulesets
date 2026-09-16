rule TTP_XOR_QUAD_CurrentVersionRun_8aff {
  strings:
    $key_8aff = { d9 90 [2] fd 9e [2] d6 b2 [2] f8 90 [2] ec 8b [2] e3 91 [2] fd 8c [2] ff 8d [2] e4 8b [2] f8 8c [2] e4 a3 }

  condition:
    any of them
}