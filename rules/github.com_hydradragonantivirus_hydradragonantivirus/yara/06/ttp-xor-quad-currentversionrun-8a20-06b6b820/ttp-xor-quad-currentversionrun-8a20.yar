rule TTP_XOR_QUAD_CurrentVersionRun_8a20 {
  strings:
    $key_8a20 = { d9 4f [2] fd 41 [2] d6 6d [2] f8 4f [2] ec 54 [2] e3 4e [2] fd 53 [2] ff 52 [2] e4 54 [2] f8 53 [2] e4 7c }

  condition:
    any of them
}