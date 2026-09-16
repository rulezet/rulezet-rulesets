rule TTP_XOR_QUAD_CurrentVersionRun_90e1 {
  strings:
    $key_90e1 = { c3 8e [2] e7 80 [2] cc ac [2] e2 8e [2] f6 95 [2] f9 8f [2] e7 92 [2] e5 93 [2] fe 95 [2] e2 92 [2] fe bd }

  condition:
    any of them
}