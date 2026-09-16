rule TTP_XOR_QUAD_CurrentVersionRun_8da2 {
  strings:
    $key_8da2 = { de cd [2] fa c3 [2] d1 ef [2] ff cd [2] eb d6 [2] e4 cc [2] fa d1 [2] f8 d0 [2] e3 d6 [2] ff d1 [2] e3 fe }

  condition:
    any of them
}