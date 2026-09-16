rule TTP_XOR_QUAD_CurrentVersionRun_bb91 {
  strings:
    $key_bb91 = { e8 fe [2] cc f0 [2] e7 dc [2] c9 fe [2] dd e5 [2] d2 ff [2] cc e2 [2] ce e3 [2] d5 e5 [2] c9 e2 [2] d5 cd }

  condition:
    any of them
}