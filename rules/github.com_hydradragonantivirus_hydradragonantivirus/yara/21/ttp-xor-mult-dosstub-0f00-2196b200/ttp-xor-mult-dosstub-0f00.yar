rule TTP_XOR_MULT_DOSStub_0f00 {
  strings:
    $key_0f00 = { 5b 68 [2] 2f 70 [2] 68 72 [2] 2f 63 [2] 61 6f [2] 6d 65 [2] 7a 6e [2] 61 20 [2] 5c }

  condition:
    any of them
}