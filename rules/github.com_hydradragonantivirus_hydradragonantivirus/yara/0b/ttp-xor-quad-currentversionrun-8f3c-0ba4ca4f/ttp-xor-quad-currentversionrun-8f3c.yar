rule TTP_XOR_QUAD_CurrentVersionRun_8f3c {
  strings:
    $key_8f3c = { dc 53 [2] f8 5d [2] d3 71 [2] fd 53 [2] e9 48 [2] e6 52 [2] f8 4f [2] fa 4e [2] e1 48 [2] fd 4f [2] e1 60 }

  condition:
    any of them
}