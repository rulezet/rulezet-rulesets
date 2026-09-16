rule TTP_XOR_QUAD_CurrentVersionRun_8f7b {
  strings:
    $key_8f7b = { dc 14 [2] f8 1a [2] d3 36 [2] fd 14 [2] e9 0f [2] e6 15 [2] f8 08 [2] fa 09 [2] e1 0f [2] fd 08 [2] e1 27 }

  condition:
    any of them
}