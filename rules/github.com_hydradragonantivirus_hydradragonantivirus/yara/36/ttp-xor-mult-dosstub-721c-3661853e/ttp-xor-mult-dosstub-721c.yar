rule TTP_XOR_MULT_DOSStub_721c {
  strings:
    $key_721c = { 26 74 [2] 52 6c [2] 15 6e [2] 52 7f [2] 1c 73 [2] 10 79 [2] 07 72 [2] 1c 3c [2] 21 }

  condition:
    any of them
}