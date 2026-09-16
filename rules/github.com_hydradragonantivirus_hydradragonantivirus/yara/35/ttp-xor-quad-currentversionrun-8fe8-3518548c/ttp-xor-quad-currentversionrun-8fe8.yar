rule TTP_XOR_QUAD_CurrentVersionRun_8fe8 {
  strings:
    $key_8fe8 = { dc 87 [2] f8 89 [2] d3 a5 [2] fd 87 [2] e9 9c [2] e6 86 [2] f8 9b [2] fa 9a [2] e1 9c [2] fd 9b [2] e1 b4 }

  condition:
    any of them
}