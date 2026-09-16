rule TTP_XOR_QUAD_CurrentVersionRun_8aeb {
  strings:
    $key_8aeb = { d9 84 [2] fd 8a [2] d6 a6 [2] f8 84 [2] ec 9f [2] e3 85 [2] fd 98 [2] ff 99 [2] e4 9f [2] f8 98 [2] e4 b7 }

  condition:
    any of them
}