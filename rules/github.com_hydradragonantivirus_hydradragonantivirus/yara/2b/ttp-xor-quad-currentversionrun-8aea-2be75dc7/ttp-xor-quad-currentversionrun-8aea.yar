rule TTP_XOR_QUAD_CurrentVersionRun_8aea {
  strings:
    $key_8aea = { d9 85 [2] fd 8b [2] d6 a7 [2] f8 85 [2] ec 9e [2] e3 84 [2] fd 99 [2] ff 98 [2] e4 9e [2] f8 99 [2] e4 b6 }

  condition:
    any of them
}