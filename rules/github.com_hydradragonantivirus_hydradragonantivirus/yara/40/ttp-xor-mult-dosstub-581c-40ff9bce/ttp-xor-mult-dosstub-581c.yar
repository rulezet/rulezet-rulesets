rule TTP_XOR_MULT_DOSStub_581c {
  strings:
    $key_581c = { 0c 74 [2] 78 6c [2] 3f 6e [2] 78 7f [2] 36 73 [2] 3a 79 [2] 2d 72 [2] 36 3c [2] 0b }

  condition:
    any of them
}