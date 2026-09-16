rule TTP_XOR_MULT_DOSStub_0b2b {
  strings:
    $key_0b2b = { 5f 43 [2] 2b 5b [2] 6c 59 [2] 2b 48 [2] 65 44 [2] 69 4e [2] 7e 45 [2] 65 0b [2] 58 }

  condition:
    any of them
}