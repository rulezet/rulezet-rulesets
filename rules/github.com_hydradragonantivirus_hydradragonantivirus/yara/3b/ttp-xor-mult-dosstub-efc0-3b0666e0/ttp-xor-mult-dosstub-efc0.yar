rule TTP_XOR_MULT_DOSStub_efc0 {
  strings:
    $key_efc0 = { bb a8 [2] cf b0 [2] 88 b2 [2] cf a3 [2] 81 af [2] 8d a5 [2] 9a ae [2] 81 e0 [2] bc }

  condition:
    any of them
}