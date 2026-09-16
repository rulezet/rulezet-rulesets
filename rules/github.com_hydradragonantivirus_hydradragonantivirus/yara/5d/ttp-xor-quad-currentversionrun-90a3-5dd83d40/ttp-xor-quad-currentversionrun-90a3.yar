rule TTP_XOR_QUAD_CurrentVersionRun_90a3 {
  strings:
    $key_90a3 = { c3 cc [2] e7 c2 [2] cc ee [2] e2 cc [2] f6 d7 [2] f9 cd [2] e7 d0 [2] e5 d1 [2] fe d7 [2] e2 d0 [2] fe ff }

  condition:
    any of them
}