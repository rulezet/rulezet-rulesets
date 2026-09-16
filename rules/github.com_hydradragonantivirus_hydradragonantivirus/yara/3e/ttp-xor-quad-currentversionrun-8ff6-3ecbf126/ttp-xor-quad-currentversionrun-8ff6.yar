rule TTP_XOR_QUAD_CurrentVersionRun_8ff6 {
  strings:
    $key_8ff6 = { dc 99 [2] f8 97 [2] d3 bb [2] fd 99 [2] e9 82 [2] e6 98 [2] f8 85 [2] fa 84 [2] e1 82 [2] fd 85 [2] e1 aa }

  condition:
    any of them
}