rule TTP_XOR_QUAD_CurrentVersionRun_8aec {
  strings:
    $key_8aec = { d9 83 [2] fd 8d [2] d6 a1 [2] f8 83 [2] ec 98 [2] e3 82 [2] fd 9f [2] ff 9e [2] e4 98 [2] f8 9f [2] e4 b0 }

  condition:
    any of them
}