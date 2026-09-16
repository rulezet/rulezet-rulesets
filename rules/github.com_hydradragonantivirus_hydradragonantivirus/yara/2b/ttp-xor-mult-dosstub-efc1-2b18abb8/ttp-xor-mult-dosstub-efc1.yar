rule TTP_XOR_MULT_DOSStub_efc1 {
  strings:
    $key_efc1 = { bb a9 [2] cf b1 [2] 88 b3 [2] cf a2 [2] 81 ae [2] 8d a4 [2] 9a af [2] 81 e1 [2] bc }

  condition:
    any of them
}