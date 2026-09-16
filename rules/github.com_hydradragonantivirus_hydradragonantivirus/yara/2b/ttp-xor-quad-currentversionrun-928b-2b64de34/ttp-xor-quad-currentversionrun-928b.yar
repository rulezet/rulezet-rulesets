rule TTP_XOR_QUAD_CurrentVersionRun_928b {
  strings:
    $key_928b = { c1 e4 [2] e5 ea [2] ce c6 [2] e0 e4 [2] f4 ff [2] fb e5 [2] e5 f8 [2] e7 f9 [2] fc ff [2] e0 f8 [2] fc d7 }

  condition:
    any of them
}