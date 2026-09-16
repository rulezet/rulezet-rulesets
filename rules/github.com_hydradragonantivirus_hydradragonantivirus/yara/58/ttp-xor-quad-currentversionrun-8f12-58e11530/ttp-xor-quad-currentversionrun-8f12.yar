rule TTP_XOR_QUAD_CurrentVersionRun_8f12 {
  strings:
    $key_8f12 = { dc 7d [2] f8 73 [2] d3 5f [2] fd 7d [2] e9 66 [2] e6 7c [2] f8 61 [2] fa 60 [2] e1 66 [2] fd 61 [2] e1 4e }

  condition:
    any of them
}