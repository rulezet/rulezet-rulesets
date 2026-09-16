rule TTP_XOR_MULT_DOSStub_1b4c {
  strings:
    $key_1b4c = { 4f 24 [2] 3b 3c [2] 7c 3e [2] 3b 2f [2] 75 23 [2] 79 29 [2] 6e 22 [2] 75 6c [2] 48 }

  condition:
    any of them
}