rule TTP_XOR_MULT_DOSStub_ef9c {
  strings:
    $key_ef9c = { bb f4 [2] cf ec [2] 88 ee [2] cf ff [2] 81 f3 [2] 8d f9 [2] 9a f2 [2] 81 bc [2] bc }

  condition:
    any of them
}