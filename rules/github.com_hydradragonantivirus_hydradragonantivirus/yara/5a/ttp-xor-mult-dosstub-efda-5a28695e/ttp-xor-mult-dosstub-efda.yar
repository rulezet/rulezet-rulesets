rule TTP_XOR_MULT_DOSStub_efda {
  strings:
    $key_efda = { bb b2 [2] cf aa [2] 88 a8 [2] cf b9 [2] 81 b5 [2] 8d bf [2] 9a b4 [2] 81 fa [2] bc }

  condition:
    any of them
}