rule TTP_XOR_MULT_DOSStub_5e1c {
  strings:
    $key_5e1c = { 0a 74 [2] 7e 6c [2] 39 6e [2] 7e 7f [2] 30 73 [2] 3c 79 [2] 2b 72 [2] 30 3c [2] 0d }

  condition:
    any of them
}