rule TTP_XOR_MULT_DOSStub_0b5b {
  strings:
    $key_0b5b = { 5f 33 [2] 2b 2b [2] 6c 29 [2] 2b 38 [2] 65 34 [2] 69 3e [2] 7e 35 [2] 65 7b [2] 58 }

  condition:
    any of them
}