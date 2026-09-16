rule TTP_XOR_MULT_DOSStub_6f36 {
  strings:
    $key_6f36 = { 3b 5e [2] 4f 46 [2] 08 44 [2] 4f 55 [2] 01 59 [2] 0d 53 [2] 1a 58 [2] 01 16 [2] 3c }

  condition:
    any of them
}