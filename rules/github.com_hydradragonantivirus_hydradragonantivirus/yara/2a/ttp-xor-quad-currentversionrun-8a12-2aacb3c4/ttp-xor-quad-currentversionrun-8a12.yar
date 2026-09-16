rule TTP_XOR_QUAD_CurrentVersionRun_8a12 {
  strings:
    $key_8a12 = { d9 7d [2] fd 73 [2] d6 5f [2] f8 7d [2] ec 66 [2] e3 7c [2] fd 61 [2] ff 60 [2] e4 66 [2] f8 61 [2] e4 4e }

  condition:
    any of them
}