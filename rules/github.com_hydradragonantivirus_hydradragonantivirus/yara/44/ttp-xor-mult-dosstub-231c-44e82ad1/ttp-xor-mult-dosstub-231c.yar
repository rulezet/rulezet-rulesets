rule TTP_XOR_MULT_DOSStub_231c {
  strings:
    $key_231c = { 77 74 [2] 03 6c [2] 44 6e [2] 03 7f [2] 4d 73 [2] 41 79 [2] 56 72 [2] 4d 3c [2] 70 }

  condition:
    any of them
}