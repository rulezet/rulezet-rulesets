rule TTP_XOR_QUAD_CurrentVersionRun_8fed {
  strings:
    $key_8fed = { dc 82 [2] f8 8c [2] d3 a0 [2] fd 82 [2] e9 99 [2] e6 83 [2] f8 9e [2] fa 9f [2] e1 99 [2] fd 9e [2] e1 b1 }

  condition:
    any of them
}