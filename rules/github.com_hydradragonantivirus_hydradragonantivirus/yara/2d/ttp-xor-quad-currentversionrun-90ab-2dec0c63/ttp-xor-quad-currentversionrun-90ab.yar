rule TTP_XOR_QUAD_CurrentVersionRun_90ab {
  strings:
    $key_90ab = { c3 c4 [2] e7 ca [2] cc e6 [2] e2 c4 [2] f6 df [2] f9 c5 [2] e7 d8 [2] e5 d9 [2] fe df [2] e2 d8 [2] fe f7 }

  condition:
    any of them
}