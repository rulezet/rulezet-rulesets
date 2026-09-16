rule TTP_XOR_QUAD_CurrentVersionRun_90ec {
  strings:
    $key_90ec = { c3 83 [2] e7 8d [2] cc a1 [2] e2 83 [2] f6 98 [2] f9 82 [2] e7 9f [2] e5 9e [2] fe 98 [2] e2 9f [2] fe b0 }

  condition:
    any of them
}