rule TTP_XOR_QUAD_CurrentVersionRun_8f3f {
  strings:
    $key_8f3f = { dc 50 [2] f8 5e [2] d3 72 [2] fd 50 [2] e9 4b [2] e6 51 [2] f8 4c [2] fa 4d [2] e1 4b [2] fd 4c [2] e1 63 }

  condition:
    any of them
}