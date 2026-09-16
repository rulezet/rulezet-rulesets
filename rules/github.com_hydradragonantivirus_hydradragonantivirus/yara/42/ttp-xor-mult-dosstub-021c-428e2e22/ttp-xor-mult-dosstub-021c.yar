rule TTP_XOR_MULT_DOSStub_021c {
  strings:
    $key_021c = { 56 74 [2] 22 6c [2] 65 6e [2] 22 7f [2] 6c 73 [2] 60 79 [2] 77 72 [2] 6c 3c [2] 51 }

  condition:
    any of them
}