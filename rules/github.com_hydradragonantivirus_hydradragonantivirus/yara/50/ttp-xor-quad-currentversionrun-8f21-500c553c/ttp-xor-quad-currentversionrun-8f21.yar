rule TTP_XOR_QUAD_CurrentVersionRun_8f21 {
  strings:
    $key_8f21 = { dc 4e [2] f8 40 [2] d3 6c [2] fd 4e [2] e9 55 [2] e6 4f [2] f8 52 [2] fa 53 [2] e1 55 [2] fd 52 [2] e1 7d }

  condition:
    any of them
}