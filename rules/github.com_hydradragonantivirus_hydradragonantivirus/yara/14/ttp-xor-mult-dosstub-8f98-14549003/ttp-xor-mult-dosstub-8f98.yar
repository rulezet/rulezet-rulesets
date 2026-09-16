rule TTP_XOR_MULT_DOSStub_8f98 {
  strings:
    $key_8f98 = { db f0 [2] af e8 [2] e8 ea [2] af fb [2] e1 f7 [2] ed fd [2] fa f6 [2] e1 b8 [2] dc }

  condition:
    any of them
}