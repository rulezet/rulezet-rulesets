rule TTP_XOR_MULT_DOSStub_761c {
  strings:
    $key_761c = { 22 74 [2] 56 6c [2] 11 6e [2] 56 7f [2] 18 73 [2] 14 79 [2] 03 72 [2] 18 3c [2] 25 }

  condition:
    any of them
}