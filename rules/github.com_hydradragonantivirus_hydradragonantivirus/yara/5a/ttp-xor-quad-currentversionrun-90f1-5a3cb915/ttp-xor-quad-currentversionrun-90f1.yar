rule TTP_XOR_QUAD_CurrentVersionRun_90f1 {
  strings:
    $key_90f1 = { c3 9e [2] e7 90 [2] cc bc [2] e2 9e [2] f6 85 [2] f9 9f [2] e7 82 [2] e5 83 [2] fe 85 [2] e2 82 [2] fe ad }

  condition:
    any of them
}