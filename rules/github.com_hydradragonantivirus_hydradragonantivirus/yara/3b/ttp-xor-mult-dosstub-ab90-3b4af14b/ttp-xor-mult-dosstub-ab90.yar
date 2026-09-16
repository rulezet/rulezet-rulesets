rule TTP_XOR_MULT_DOSStub_ab90 {
  strings:
    $key_ab90 = { ff f8 [2] 8b e0 [2] cc e2 [2] 8b f3 [2] c5 ff [2] c9 f5 [2] de fe [2] c5 b0 [2] f8 }

  condition:
    any of them
}