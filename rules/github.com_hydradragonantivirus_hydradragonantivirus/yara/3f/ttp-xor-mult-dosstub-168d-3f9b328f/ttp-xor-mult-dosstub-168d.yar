rule TTP_XOR_MULT_DOSStub_168d {
  strings:
    $key_168d = { 42 e5 [2] 36 fd [2] 71 ff [2] 36 ee [2] 78 e2 [2] 74 e8 [2] 63 e3 [2] 78 ad [2] 45 }

  condition:
    any of them
}