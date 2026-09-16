rule TTP_XOR_QUAD_CurrentVersionRun_8a30 {
  strings:
    $key_8a30 = { d9 5f [2] fd 51 [2] d6 7d [2] f8 5f [2] ec 44 [2] e3 5e [2] fd 43 [2] ff 42 [2] e4 44 [2] f8 43 [2] e4 6c }

  condition:
    any of them
}