rule TTP_XOR_QUAD_CurrentVersionRun_8f78 {
  strings:
    $key_8f78 = { dc 17 [2] f8 19 [2] d3 35 [2] fd 17 [2] e9 0c [2] e6 16 [2] f8 0b [2] fa 0a [2] e1 0c [2] fd 0b [2] e1 24 }

  condition:
    any of them
}