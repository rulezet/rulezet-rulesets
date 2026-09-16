rule TTP_XOR_MULT_DOSStub_1111 {
  strings:
    $key_1111 = { 45 79 [2] 31 61 [2] 76 63 [2] 31 72 [2] 7f 7e [2] 73 74 [2] 64 7f [2] 7f 31 [2] 42 }

  condition:
    any of them
}