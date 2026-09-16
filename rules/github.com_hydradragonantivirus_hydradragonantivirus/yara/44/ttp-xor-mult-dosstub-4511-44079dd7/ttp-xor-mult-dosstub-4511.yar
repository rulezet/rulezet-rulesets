rule TTP_XOR_MULT_DOSStub_4511 {
  strings:
    $key_4511 = { 11 79 [2] 65 61 [2] 22 63 [2] 65 72 [2] 2b 7e [2] 27 74 [2] 30 7f [2] 2b 31 [2] 16 }

  condition:
    any of them
}