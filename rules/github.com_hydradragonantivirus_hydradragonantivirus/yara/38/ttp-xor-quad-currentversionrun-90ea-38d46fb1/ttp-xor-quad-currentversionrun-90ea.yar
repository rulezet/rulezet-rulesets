rule TTP_XOR_QUAD_CurrentVersionRun_90ea {
  strings:
    $key_90ea = { c3 85 [2] e7 8b [2] cc a7 [2] e2 85 [2] f6 9e [2] f9 84 [2] e7 99 [2] e5 98 [2] fe 9e [2] e2 99 [2] fe b6 }

  condition:
    any of them
}