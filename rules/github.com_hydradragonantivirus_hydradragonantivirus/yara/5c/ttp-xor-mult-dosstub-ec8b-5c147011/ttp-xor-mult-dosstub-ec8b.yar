rule TTP_XOR_MULT_DOSStub_ec8b {
  strings:
    $key_ec8b = { b8 e3 [2] cc fb [2] 8b f9 [2] cc e8 [2] 82 e4 [2] 8e ee [2] 99 e5 [2] 82 ab [2] bf }

  condition:
    any of them
}