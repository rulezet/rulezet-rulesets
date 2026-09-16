rule TTP_XOR_QUAD_CurrentVersionRun_8afc {
  strings:
    $key_8afc = { d9 93 [2] fd 9d [2] d6 b1 [2] f8 93 [2] ec 88 [2] e3 92 [2] fd 8f [2] ff 8e [2] e4 88 [2] f8 8f [2] e4 a0 }

  condition:
    any of them
}