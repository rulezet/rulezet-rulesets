rule TTP_XOR_MULT_DOSStub_5e36 {
  strings:
    $key_5e36 = { 0a 5e [2] 7e 46 [2] 39 44 [2] 7e 55 [2] 30 59 [2] 3c 53 [2] 2b 58 [2] 30 16 [2] 0d }

  condition:
    any of them
}