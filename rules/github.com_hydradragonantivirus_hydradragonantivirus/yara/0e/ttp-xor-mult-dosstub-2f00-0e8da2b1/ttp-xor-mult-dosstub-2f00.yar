rule TTP_XOR_MULT_DOSStub_2f00 {
  strings:
    $key_2f00 = { 7b 68 [2] 0f 70 [2] 48 72 [2] 0f 63 [2] 41 6f [2] 4d 65 [2] 5a 6e [2] 41 20 [2] 7c }

  condition:
    any of them
}