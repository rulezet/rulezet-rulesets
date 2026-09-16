rule TTP_XOR_QUAD_CurrentVersionRun_90f2 {
  strings:
    $key_90f2 = { c3 9d [2] e7 93 [2] cc bf [2] e2 9d [2] f6 86 [2] f9 9c [2] e7 81 [2] e5 80 [2] fe 86 [2] e2 81 [2] fe ae }

  condition:
    any of them
}