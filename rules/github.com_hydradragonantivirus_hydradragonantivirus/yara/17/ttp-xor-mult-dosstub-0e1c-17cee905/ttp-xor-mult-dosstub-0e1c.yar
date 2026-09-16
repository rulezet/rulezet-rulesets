rule TTP_XOR_MULT_DOSStub_0e1c {
  strings:
    $key_0e1c = { 5a 74 [2] 2e 6c [2] 69 6e [2] 2e 7f [2] 60 73 [2] 6c 79 [2] 7b 72 [2] 60 3c [2] 5d }

  condition:
    any of them
}