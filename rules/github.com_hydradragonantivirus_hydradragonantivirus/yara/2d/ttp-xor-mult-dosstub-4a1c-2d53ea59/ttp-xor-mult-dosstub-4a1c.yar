rule TTP_XOR_MULT_DOSStub_4a1c {
  strings:
    $key_4a1c = { 1e 74 [2] 6a 6c [2] 2d 6e [2] 6a 7f [2] 24 73 [2] 28 79 [2] 3f 72 [2] 24 3c [2] 19 }

  condition:
    any of them
}