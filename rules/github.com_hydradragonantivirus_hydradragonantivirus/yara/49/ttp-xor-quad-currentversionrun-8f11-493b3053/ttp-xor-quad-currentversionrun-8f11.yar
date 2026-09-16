rule TTP_XOR_QUAD_CurrentVersionRun_8f11 {
  strings:
    $key_8f11 = { dc 7e [2] f8 70 [2] d3 5c [2] fd 7e [2] e9 65 [2] e6 7f [2] f8 62 [2] fa 63 [2] e1 65 [2] fd 62 [2] e1 4d }

  condition:
    any of them
}