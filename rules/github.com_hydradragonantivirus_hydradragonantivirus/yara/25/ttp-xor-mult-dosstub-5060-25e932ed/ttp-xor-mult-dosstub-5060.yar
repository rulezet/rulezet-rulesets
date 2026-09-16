rule TTP_XOR_MULT_DOSStub_5060 {
  strings:
    $key_5060 = { 04 08 [2] 70 10 [2] 37 12 [2] 70 03 [2] 3e 0f [2] 32 05 [2] 25 0e [2] 3e 40 [2] 03 }

  condition:
    any of them
}