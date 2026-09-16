rule TTP_XOR_MULT_DOSStub_0f17 {
  strings:
    $key_0f17 = { 5b 7f [2] 2f 67 [2] 68 65 [2] 2f 74 [2] 61 78 [2] 6d 72 [2] 7a 79 [2] 61 37 [2] 5c }

  condition:
    any of them
}