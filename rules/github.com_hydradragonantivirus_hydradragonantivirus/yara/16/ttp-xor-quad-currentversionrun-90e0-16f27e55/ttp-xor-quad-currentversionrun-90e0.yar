rule TTP_XOR_QUAD_CurrentVersionRun_90e0 {
  strings:
    $key_90e0 = { c3 8f [2] e7 81 [2] cc ad [2] e2 8f [2] f6 94 [2] f9 8e [2] e7 93 [2] e5 92 [2] fe 94 [2] e2 93 [2] fe bc }

  condition:
    any of them
}