rule TTP_XOR_MULT_DOSStub_094c {
  strings:
    $key_094c = { 5d 24 [2] 29 3c [2] 6e 3e [2] 29 2f [2] 67 23 [2] 6b 29 [2] 7c 22 [2] 67 6c [2] 5a }

  condition:
    any of them
}