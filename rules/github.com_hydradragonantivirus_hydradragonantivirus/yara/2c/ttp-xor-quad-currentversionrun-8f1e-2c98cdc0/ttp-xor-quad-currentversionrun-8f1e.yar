rule TTP_XOR_QUAD_CurrentVersionRun_8f1e {
  strings:
    $key_8f1e = { dc 71 [2] f8 7f [2] d3 53 [2] fd 71 [2] e9 6a [2] e6 70 [2] f8 6d [2] fa 6c [2] e1 6a [2] fd 6d [2] e1 42 }

  condition:
    any of them
}