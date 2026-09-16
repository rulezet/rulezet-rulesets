rule TTP_XOR_MULT_DOSStub_181c {
  strings:
    $key_181c = { 4c 74 [2] 38 6c [2] 7f 6e [2] 38 7f [2] 76 73 [2] 7a 79 [2] 6d 72 [2] 76 3c [2] 4b }

  condition:
    any of them
}