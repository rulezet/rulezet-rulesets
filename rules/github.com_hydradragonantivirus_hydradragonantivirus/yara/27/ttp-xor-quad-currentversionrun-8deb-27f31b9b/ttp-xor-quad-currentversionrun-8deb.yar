rule TTP_XOR_QUAD_CurrentVersionRun_8deb {
  strings:
    $key_8deb = { de 84 [2] fa 8a [2] d1 a6 [2] ff 84 [2] eb 9f [2] e4 85 [2] fa 98 [2] f8 99 [2] e3 9f [2] ff 98 [2] e3 b7 }

  condition:
    any of them
}