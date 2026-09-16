rule TTP_XOR_MULT_DOSStub_1b7c {
  strings:
    $key_1b7c = { 4f 14 [2] 3b 0c [2] 7c 0e [2] 3b 1f [2] 75 13 [2] 79 19 [2] 6e 12 [2] 75 5c [2] 48 }

  condition:
    any of them
}