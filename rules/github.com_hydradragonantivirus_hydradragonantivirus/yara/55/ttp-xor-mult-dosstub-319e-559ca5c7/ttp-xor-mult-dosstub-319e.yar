rule TTP_XOR_MULT_DOSStub_319e {
  strings:
    $key_319e = { 65 f6 [2] 11 ee [2] 56 ec [2] 11 fd [2] 5f f1 [2] 53 fb [2] 44 f0 [2] 5f be [2] 62 }

  condition:
    any of them
}