rule TTP_XOR_QUAD_CurrentVersionRun_8ff0 {
  strings:
    $key_8ff0 = { dc 9f [2] f8 91 [2] d3 bd [2] fd 9f [2] e9 84 [2] e6 9e [2] f8 83 [2] fa 82 [2] e1 84 [2] fd 83 [2] e1 ac }

  condition:
    any of them
}