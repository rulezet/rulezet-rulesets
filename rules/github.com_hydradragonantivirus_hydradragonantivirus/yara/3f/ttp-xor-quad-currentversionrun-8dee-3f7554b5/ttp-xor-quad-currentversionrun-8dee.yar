rule TTP_XOR_QUAD_CurrentVersionRun_8dee {
  strings:
    $key_8dee = { de 81 [2] fa 8f [2] d1 a3 [2] ff 81 [2] eb 9a [2] e4 80 [2] fa 9d [2] f8 9c [2] e3 9a [2] ff 9d [2] e3 b2 }

  condition:
    any of them
}