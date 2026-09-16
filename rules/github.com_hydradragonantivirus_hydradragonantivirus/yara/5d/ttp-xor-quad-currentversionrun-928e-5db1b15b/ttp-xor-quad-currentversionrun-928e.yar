rule TTP_XOR_QUAD_CurrentVersionRun_928e {
  strings:
    $key_928e = { c1 e1 [2] e5 ef [2] ce c3 [2] e0 e1 [2] f4 fa [2] fb e0 [2] e5 fd [2] e7 fc [2] fc fa [2] e0 fd [2] fc d2 }

  condition:
    any of them
}