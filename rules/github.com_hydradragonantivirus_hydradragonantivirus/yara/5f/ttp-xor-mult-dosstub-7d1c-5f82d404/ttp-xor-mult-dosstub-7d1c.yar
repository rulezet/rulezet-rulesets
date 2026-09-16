rule TTP_XOR_MULT_DOSStub_7d1c {
  strings:
    $key_7d1c = { 29 74 [2] 5d 6c [2] 1a 6e [2] 5d 7f [2] 13 73 [2] 1f 79 [2] 08 72 [2] 13 3c [2] 2e }

  condition:
    any of them
}