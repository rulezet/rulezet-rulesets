rule TTP_XOR_QUAD_CurrentVersionRun_8fee {
  strings:
    $key_8fee = { dc 81 [2] f8 8f [2] d3 a3 [2] fd 81 [2] e9 9a [2] e6 80 [2] f8 9d [2] fa 9c [2] e1 9a [2] fd 9d [2] e1 b2 }

  condition:
    any of them
}