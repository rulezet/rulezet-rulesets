rule TTP_XOR_MULT_DOSStub_5011 {
  strings:
    $key_5011 = { 04 79 [2] 70 61 [2] 37 63 [2] 70 72 [2] 3e 7e [2] 32 74 [2] 25 7f [2] 3e 31 [2] 03 }

  condition:
    any of them
}