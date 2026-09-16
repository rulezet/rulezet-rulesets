rule TTP_XOR_MULT_DOSStub_0900 {
  strings:
    $key_0900 = { 5d 68 [2] 29 70 [2] 6e 72 [2] 29 63 [2] 67 6f [2] 6b 65 [2] 7c 6e [2] 67 20 [2] 5a }

  condition:
    any of them
}