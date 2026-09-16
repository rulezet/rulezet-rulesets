rule TTP_XOR_QUAD_CurrentVersionRun_8ffb {
  strings:
    $key_8ffb = { dc 94 [2] f8 9a [2] d3 b6 [2] fd 94 [2] e9 8f [2] e6 95 [2] f8 88 [2] fa 89 [2] e1 8f [2] fd 88 [2] e1 a7 }

  condition:
    any of them
}