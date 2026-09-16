rule TTP_XOR_MULT_DOSStub_ab93 {
  strings:
    $key_ab93 = { ff fb [2] 8b e3 [2] cc e1 [2] 8b f0 [2] c5 fc [2] c9 f6 [2] de fd [2] c5 b3 [2] f8 }

  condition:
    any of them
}