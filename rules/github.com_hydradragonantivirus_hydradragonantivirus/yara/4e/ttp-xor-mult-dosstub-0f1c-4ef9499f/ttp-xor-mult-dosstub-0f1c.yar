rule TTP_XOR_MULT_DOSStub_0f1c {
  strings:
    $key_0f1c = { 5b 74 [2] 2f 6c [2] 68 6e [2] 2f 7f [2] 61 73 [2] 6d 79 [2] 7a 72 [2] 61 3c [2] 5c }

  condition:
    any of them
}