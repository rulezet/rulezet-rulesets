rule TTP_XOR_QUAD_CurrentVersionRun_8f31 {
  strings:
    $key_8f31 = { dc 5e [2] f8 50 [2] d3 7c [2] fd 5e [2] e9 45 [2] e6 5f [2] f8 42 [2] fa 43 [2] e1 45 [2] fd 42 [2] e1 6d }

  condition:
    any of them
}