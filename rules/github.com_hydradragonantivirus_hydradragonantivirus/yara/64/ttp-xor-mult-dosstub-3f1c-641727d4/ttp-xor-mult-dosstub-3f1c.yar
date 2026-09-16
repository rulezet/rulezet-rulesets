rule TTP_XOR_MULT_DOSStub_3f1c {
  strings:
    $key_3f1c = { 6b 74 [2] 1f 6c [2] 58 6e [2] 1f 7f [2] 51 73 [2] 5d 79 [2] 4a 72 [2] 51 3c [2] 6c }

  condition:
    any of them
}