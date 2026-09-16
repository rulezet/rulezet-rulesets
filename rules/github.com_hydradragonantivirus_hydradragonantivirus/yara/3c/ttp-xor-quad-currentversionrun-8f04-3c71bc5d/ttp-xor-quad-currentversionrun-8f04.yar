rule TTP_XOR_QUAD_CurrentVersionRun_8f04 {
  strings:
    $key_8f04 = { dc 6b [2] f8 65 [2] d3 49 [2] fd 6b [2] e9 70 [2] e6 6a [2] f8 77 [2] fa 76 [2] e1 70 [2] fd 77 [2] e1 58 }

  condition:
    any of them
}