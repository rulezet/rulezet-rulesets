rule TTP_XOR_QUAD_CurrentVersionRun_8f37 {
  strings:
    $key_8f37 = { dc 58 [2] f8 56 [2] d3 7a [2] fd 58 [2] e9 43 [2] e6 59 [2] f8 44 [2] fa 45 [2] e1 43 [2] fd 44 [2] e1 6b }

  condition:
    any of them
}