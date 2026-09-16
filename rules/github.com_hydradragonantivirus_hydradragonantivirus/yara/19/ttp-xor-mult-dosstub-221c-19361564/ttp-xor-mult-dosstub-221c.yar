rule TTP_XOR_MULT_DOSStub_221c {
  strings:
    $key_221c = { 76 74 [2] 02 6c [2] 45 6e [2] 02 7f [2] 4c 73 [2] 40 79 [2] 57 72 [2] 4c 3c [2] 71 }

  condition:
    any of them
}