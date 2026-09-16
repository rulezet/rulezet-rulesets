rule TTP_XOR_MULT_DOSStub_1900 {
  strings:
    $key_1900 = { 4d 68 [2] 39 70 [2] 7e 72 [2] 39 63 [2] 77 6f [2] 7b 65 [2] 6c 6e [2] 77 20 [2] 4a }

  condition:
    any of them
}