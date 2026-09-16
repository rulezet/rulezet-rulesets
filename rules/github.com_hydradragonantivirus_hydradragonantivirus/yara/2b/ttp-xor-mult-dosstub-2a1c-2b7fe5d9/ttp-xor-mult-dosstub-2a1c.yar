rule TTP_XOR_MULT_DOSStub_2a1c {
  strings:
    $key_2a1c = { 7e 74 [2] 0a 6c [2] 4d 6e [2] 0a 7f [2] 44 73 [2] 48 79 [2] 5f 72 [2] 44 3c [2] 79 }

  condition:
    any of them
}