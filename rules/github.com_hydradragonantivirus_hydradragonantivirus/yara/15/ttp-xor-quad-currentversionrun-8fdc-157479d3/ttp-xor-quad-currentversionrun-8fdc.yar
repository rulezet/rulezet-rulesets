rule TTP_XOR_QUAD_CurrentVersionRun_8fdc {
  strings:
    $key_8fdc = { dc b3 [2] f8 bd [2] d3 91 [2] fd b3 [2] e9 a8 [2] e6 b2 [2] f8 af [2] fa ae [2] e1 a8 [2] fd af [2] e1 80 }

  condition:
    any of them
}