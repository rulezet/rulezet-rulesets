rule TTP_XOR_QUAD_CurrentVersionRun_90a6 {
  strings:
    $key_90a6 = { c3 c9 [2] e7 c7 [2] cc eb [2] e2 c9 [2] f6 d2 [2] f9 c8 [2] e7 d5 [2] e5 d4 [2] fe d2 [2] e2 d5 [2] fe fa }

  condition:
    any of them
}