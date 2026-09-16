rule TTP_XOR_MULT_DOSStub_5900 {
  strings:
    $key_5900 = { 0d 68 [2] 79 70 [2] 3e 72 [2] 79 63 [2] 37 6f [2] 3b 65 [2] 2c 6e [2] 37 20 [2] 0a }

  condition:
    any of them
}