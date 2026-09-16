rule TTP_XOR_MULT_DOSStub_1137 {
  strings:
    $key_1137 = { 45 5f [2] 31 47 [2] 76 45 [2] 31 54 [2] 7f 58 [2] 73 52 [2] 64 59 [2] 7f 17 [2] 42 }

  condition:
    any of them
}