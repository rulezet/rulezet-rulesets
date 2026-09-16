rule TTP_XOR_QUAD_CurrentVersionRun_898e {
  strings:
    $key_898e = { da e1 [2] fe ef [2] d5 c3 [2] fb e1 [2] ef fa [2] e0 e0 [2] fe fd [2] fc fc [2] e7 fa [2] fb fd [2] e7 d2 }

  condition:
    any of them
}