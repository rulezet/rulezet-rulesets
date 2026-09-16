rule TTP_XOR_QUAD_CurrentVersionRun_8d3e {
  strings:
    $key_8d3e = { de 51 [2] fa 5f [2] d1 73 [2] ff 51 [2] eb 4a [2] e4 50 [2] fa 4d [2] f8 4c [2] e3 4a [2] ff 4d [2] e3 62 }

  condition:
    any of them
}