rule TTP_XOR_QUAD_CurrentVersionRun_8af1 {
  strings:
    $key_8af1 = { d9 9e [2] fd 90 [2] d6 bc [2] f8 9e [2] ec 85 [2] e3 9f [2] fd 82 [2] ff 83 [2] e4 85 [2] f8 82 [2] e4 ad }

  condition:
    any of them
}