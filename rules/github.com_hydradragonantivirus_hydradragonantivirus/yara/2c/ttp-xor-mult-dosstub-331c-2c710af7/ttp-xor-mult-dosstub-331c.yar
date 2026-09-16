rule TTP_XOR_MULT_DOSStub_331c {
  strings:
    $key_331c = { 67 74 [2] 13 6c [2] 54 6e [2] 13 7f [2] 5d 73 [2] 51 79 [2] 46 72 [2] 5d 3c [2] 60 }

  condition:
    any of them
}