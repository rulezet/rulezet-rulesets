rule TTP_XOR_QUAD_CurrentVersionRun_8f05 {
  strings:
    $key_8f05 = { dc 6a [2] f8 64 [2] d3 48 [2] fd 6a [2] e9 71 [2] e6 6b [2] f8 76 [2] fa 77 [2] e1 71 [2] fd 76 [2] e1 59 }

  condition:
    any of them
}