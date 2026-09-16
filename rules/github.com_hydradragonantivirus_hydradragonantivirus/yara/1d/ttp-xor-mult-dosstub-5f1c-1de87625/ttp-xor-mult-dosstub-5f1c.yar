rule TTP_XOR_MULT_DOSStub_5f1c {
  strings:
    $key_5f1c = { 0b 74 [2] 7f 6c [2] 38 6e [2] 7f 7f [2] 31 73 [2] 3d 79 [2] 2a 72 [2] 31 3c [2] 0c }

  condition:
    any of them
}