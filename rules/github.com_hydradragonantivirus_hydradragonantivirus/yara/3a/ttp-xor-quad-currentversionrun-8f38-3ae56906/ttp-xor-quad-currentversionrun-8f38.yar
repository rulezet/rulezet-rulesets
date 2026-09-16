rule TTP_XOR_QUAD_CurrentVersionRun_8f38 {
  strings:
    $key_8f38 = { dc 57 [2] f8 59 [2] d3 75 [2] fd 57 [2] e9 4c [2] e6 56 [2] f8 4b [2] fa 4a [2] e1 4c [2] fd 4b [2] e1 64 }

  condition:
    any of them
}