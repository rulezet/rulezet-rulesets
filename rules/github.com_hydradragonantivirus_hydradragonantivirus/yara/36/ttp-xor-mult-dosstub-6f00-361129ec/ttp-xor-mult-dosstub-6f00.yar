rule TTP_XOR_MULT_DOSStub_6f00 {
  strings:
    $key_6f00 = { 3b 68 [2] 4f 70 [2] 08 72 [2] 4f 63 [2] 01 6f [2] 0d 65 [2] 1a 6e [2] 01 20 [2] 3c }

  condition:
    any of them
}