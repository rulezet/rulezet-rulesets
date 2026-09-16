rule TTP_XOR_QUAD_CurrentVersionRun_aa88 {
  strings:
    $key_aa88 = { f9 e7 [2] dd e9 [2] f6 c5 [2] d8 e7 [2] cc fc [2] c3 e6 [2] dd fb [2] df fa [2] c4 fc [2] d8 fb [2] c4 d4 }

  condition:
    any of them
}