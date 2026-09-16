rule TTP_XOR_MULT_DOSStub_0b7c {
  strings:
    $key_0b7c = { 5f 14 [2] 2b 0c [2] 6c 0e [2] 2b 1f [2] 65 13 [2] 69 19 [2] 7e 12 [2] 65 5c [2] 58 }

  condition:
    any of them
}