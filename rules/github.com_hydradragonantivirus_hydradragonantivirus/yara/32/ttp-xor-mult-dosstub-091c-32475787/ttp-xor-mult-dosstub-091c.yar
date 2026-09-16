rule TTP_XOR_MULT_DOSStub_091c {
  strings:
    $key_091c = { 5d 74 [2] 29 6c [2] 6e 6e [2] 29 7f [2] 67 73 [2] 6b 79 [2] 7c 72 [2] 67 3c [2] 5a }

  condition:
    any of them
}