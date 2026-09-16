rule TTP_XOR_QUAD_CurrentVersionRun_8ae0 {
  strings:
    $key_8ae0 = { d9 8f [2] fd 81 [2] d6 ad [2] f8 8f [2] ec 94 [2] e3 8e [2] fd 93 [2] ff 92 [2] e4 94 [2] f8 93 [2] e4 bc }

  condition:
    any of them
}