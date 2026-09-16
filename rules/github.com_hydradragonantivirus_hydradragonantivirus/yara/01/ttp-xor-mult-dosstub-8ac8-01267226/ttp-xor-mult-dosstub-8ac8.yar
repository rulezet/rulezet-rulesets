rule TTP_XOR_MULT_DOSStub_8ac8 {
  strings:
    $key_8ac8 = { de a0 [2] aa b8 [2] ed ba [2] aa ab [2] e4 a7 [2] e8 ad [2] ff a6 [2] e4 e8 [2] d9 }

  condition:
    any of them
}