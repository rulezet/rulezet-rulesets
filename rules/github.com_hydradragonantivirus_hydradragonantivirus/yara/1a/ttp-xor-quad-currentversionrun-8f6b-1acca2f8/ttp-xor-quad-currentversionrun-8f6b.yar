rule TTP_XOR_QUAD_CurrentVersionRun_8f6b {
  strings:
    $key_8f6b = { dc 04 [2] f8 0a [2] d3 26 [2] fd 04 [2] e9 1f [2] e6 05 [2] f8 18 [2] fa 19 [2] e1 1f [2] fd 18 [2] e1 37 }

  condition:
    any of them
}