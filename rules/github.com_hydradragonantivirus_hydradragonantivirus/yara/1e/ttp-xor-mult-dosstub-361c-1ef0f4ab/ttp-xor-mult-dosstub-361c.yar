rule TTP_XOR_MULT_DOSStub_361c {
  strings:
    $key_361c = { 62 74 [2] 16 6c [2] 51 6e [2] 16 7f [2] 58 73 [2] 54 79 [2] 43 72 [2] 58 3c [2] 65 }

  condition:
    any of them
}