rule TTP_XOR_MULT_DOSStub_ef9e {
  strings:
    $key_ef9e = { bb f6 [2] cf ee [2] 88 ec [2] cf fd [2] 81 f1 [2] 8d fb [2] 9a f0 [2] 81 be [2] bc }

  condition:
    any of them
}