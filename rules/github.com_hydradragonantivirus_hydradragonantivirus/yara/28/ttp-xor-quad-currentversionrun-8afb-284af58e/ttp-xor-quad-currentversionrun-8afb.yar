rule TTP_XOR_QUAD_CurrentVersionRun_8afb {
  strings:
    $key_8afb = { d9 94 [2] fd 9a [2] d6 b6 [2] f8 94 [2] ec 8f [2] e3 95 [2] fd 88 [2] ff 89 [2] e4 8f [2] f8 88 [2] e4 a7 }

  condition:
    any of them
}