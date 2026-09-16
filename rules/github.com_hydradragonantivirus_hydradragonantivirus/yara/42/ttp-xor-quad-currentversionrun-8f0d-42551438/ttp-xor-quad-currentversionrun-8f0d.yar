rule TTP_XOR_QUAD_CurrentVersionRun_8f0d {
  strings:
    $key_8f0d = { dc 62 [2] f8 6c [2] d3 40 [2] fd 62 [2] e9 79 [2] e6 63 [2] f8 7e [2] fa 7f [2] e1 79 [2] fd 7e [2] e1 51 }

  condition:
    any of them
}