rule TTP_XOR_MULT_DOSStub_2f06 {
  strings:
    $key_2f06 = { 7b 6e [2] 0f 76 [2] 48 74 [2] 0f 65 [2] 41 69 [2] 4d 63 [2] 5a 68 [2] 41 26 [2] 7c }

  condition:
    any of them
}