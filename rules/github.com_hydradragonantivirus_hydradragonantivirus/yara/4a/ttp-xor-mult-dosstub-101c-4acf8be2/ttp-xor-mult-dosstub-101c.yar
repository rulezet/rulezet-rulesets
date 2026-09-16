rule TTP_XOR_MULT_DOSStub_101c {
  strings:
    $key_101c = { 44 74 [2] 30 6c [2] 77 6e [2] 30 7f [2] 7e 73 [2] 72 79 [2] 65 72 [2] 7e 3c [2] 43 }

  condition:
    any of them
}