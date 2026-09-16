rule TTP_XOR_QUAD_CurrentVersionRun_8ff8 {
  strings:
    $key_8ff8 = { dc 97 [2] f8 99 [2] d3 b5 [2] fd 97 [2] e9 8c [2] e6 96 [2] f8 8b [2] fa 8a [2] e1 8c [2] fd 8b [2] e1 a4 }

  condition:
    any of them
}