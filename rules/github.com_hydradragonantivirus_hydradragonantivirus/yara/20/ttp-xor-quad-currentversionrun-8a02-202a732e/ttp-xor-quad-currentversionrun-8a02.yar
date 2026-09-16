rule TTP_XOR_QUAD_CurrentVersionRun_8a02 {
  strings:
    $key_8a02 = { d9 6d [2] fd 63 [2] d6 4f [2] f8 6d [2] ec 76 [2] e3 6c [2] fd 71 [2] ff 70 [2] e4 76 [2] f8 71 [2] e4 5e }

  condition:
    any of them
}