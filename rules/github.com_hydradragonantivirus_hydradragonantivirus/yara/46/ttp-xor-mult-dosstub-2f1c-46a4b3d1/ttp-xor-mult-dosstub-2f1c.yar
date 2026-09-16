rule TTP_XOR_MULT_DOSStub_2f1c {
  strings:
    $key_2f1c = { 7b 74 [2] 0f 6c [2] 48 6e [2] 0f 7f [2] 41 73 [2] 4d 79 [2] 5a 72 [2] 41 3c [2] 7c }

  condition:
    any of them
}