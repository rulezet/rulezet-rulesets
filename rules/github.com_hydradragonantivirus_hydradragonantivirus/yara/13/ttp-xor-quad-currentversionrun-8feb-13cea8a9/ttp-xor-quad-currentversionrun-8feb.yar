rule TTP_XOR_QUAD_CurrentVersionRun_8feb {
  strings:
    $key_8feb = { dc 84 [2] f8 8a [2] d3 a6 [2] fd 84 [2] e9 9f [2] e6 85 [2] f8 98 [2] fa 99 [2] e1 9f [2] fd 98 [2] e1 b7 }

  condition:
    any of them
}