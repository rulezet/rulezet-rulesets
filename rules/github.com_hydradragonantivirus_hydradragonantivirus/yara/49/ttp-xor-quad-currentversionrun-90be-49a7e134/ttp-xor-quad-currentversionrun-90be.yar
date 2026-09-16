rule TTP_XOR_QUAD_CurrentVersionRun_90be {
  strings:
    $key_90be = { c3 d1 [2] e7 df [2] cc f3 [2] e2 d1 [2] f6 ca [2] f9 d0 [2] e7 cd [2] e5 cc [2] fe ca [2] e2 cd [2] fe e2 }

  condition:
    any of them
}