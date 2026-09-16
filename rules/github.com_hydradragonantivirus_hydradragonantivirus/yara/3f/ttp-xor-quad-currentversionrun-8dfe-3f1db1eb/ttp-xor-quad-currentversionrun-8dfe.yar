rule TTP_XOR_QUAD_CurrentVersionRun_8dfe {
  strings:
    $key_8dfe = { de 91 [2] fa 9f [2] d1 b3 [2] ff 91 [2] eb 8a [2] e4 90 [2] fa 8d [2] f8 8c [2] e3 8a [2] ff 8d [2] e3 a2 }

  condition:
    any of them
}