rule TTP_XOR_MULT_DOSStub_1131 {
  strings:
    $key_1131 = { 45 59 [2] 31 41 [2] 76 43 [2] 31 52 [2] 7f 5e [2] 73 54 [2] 64 5f [2] 7f 11 [2] 42 }

  condition:
    any of them
}