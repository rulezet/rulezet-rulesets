rule TTP_XOR_QUAD_CurrentVersionRun_8f0f {
  strings:
    $key_8f0f = { dc 60 [2] f8 6e [2] d3 42 [2] fd 60 [2] e9 7b [2] e6 61 [2] f8 7c [2] fa 7d [2] e1 7b [2] fd 7c [2] e1 53 }

  condition:
    any of them
}