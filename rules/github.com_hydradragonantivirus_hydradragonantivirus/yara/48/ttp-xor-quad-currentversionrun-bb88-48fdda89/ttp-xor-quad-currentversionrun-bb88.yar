rule TTP_XOR_QUAD_CurrentVersionRun_bb88 {
  strings:
    $key_bb88 = { e8 e7 [2] cc e9 [2] e7 c5 [2] c9 e7 [2] dd fc [2] d2 e6 [2] cc fb [2] ce fa [2] d5 fc [2] c9 fb [2] d5 d4 }

  condition:
    any of them
}