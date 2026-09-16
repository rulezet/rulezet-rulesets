rule TTP_XOR_MULT_DOSStub_efc5 {
  strings:
    $key_efc5 = { bb ad [2] cf b5 [2] 88 b7 [2] cf a6 [2] 81 aa [2] 8d a0 [2] 9a ab [2] 81 e5 [2] bc }

  condition:
    any of them
}