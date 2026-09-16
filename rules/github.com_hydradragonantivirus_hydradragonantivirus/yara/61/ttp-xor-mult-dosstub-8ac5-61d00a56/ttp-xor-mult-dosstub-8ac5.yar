rule TTP_XOR_MULT_DOSStub_8ac5 {
  strings:
    $key_8ac5 = { de ad [2] aa b5 [2] ed b7 [2] aa a6 [2] e4 aa [2] e8 a0 [2] ff ab [2] e4 e5 [2] d9 }

  condition:
    any of them
}