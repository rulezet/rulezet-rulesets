rule TTP_XOR_QUAD_CurrentVersionRun_90f7 {
  strings:
    $key_90f7 = { c3 98 [2] e7 96 [2] cc ba [2] e2 98 [2] f6 83 [2] f9 99 [2] e7 84 [2] e5 85 [2] fe 83 [2] e2 84 [2] fe ab }

  condition:
    any of them
}