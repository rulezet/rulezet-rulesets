rule TTP_XOR_QUAD_CurrentVersionRun_8d3f {
  strings:
    $key_8d3f = { de 50 [2] fa 5e [2] d1 72 [2] ff 50 [2] eb 4b [2] e4 51 [2] fa 4c [2] f8 4d [2] e3 4b [2] ff 4c [2] e3 63 }

  condition:
    any of them
}