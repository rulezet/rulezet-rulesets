rule TTP_XOR_MULT_DOSStub_2f17 {
  strings:
    $key_2f17 = { 7b 7f [2] 0f 67 [2] 48 65 [2] 0f 74 [2] 41 78 [2] 4d 72 [2] 5a 79 [2] 41 37 [2] 7c }

  condition:
    any of them
}