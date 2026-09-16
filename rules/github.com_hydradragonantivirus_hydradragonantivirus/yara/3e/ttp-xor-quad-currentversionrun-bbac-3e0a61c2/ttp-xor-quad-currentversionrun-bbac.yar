rule TTP_XOR_QUAD_CurrentVersionRun_bbac {
  strings:
    $key_bbac = { e8 c3 [2] cc cd [2] e7 e1 [2] c9 c3 [2] dd d8 [2] d2 c2 [2] cc df [2] ce de [2] d5 d8 [2] c9 df [2] d5 f0 }

  condition:
    any of them
}