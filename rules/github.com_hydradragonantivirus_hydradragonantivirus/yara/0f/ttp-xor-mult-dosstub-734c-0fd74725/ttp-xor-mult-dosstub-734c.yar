rule TTP_XOR_MULT_DOSStub_734c {
  strings:
    $key_734c = { 27 24 [2] 53 3c [2] 14 3e [2] 53 2f [2] 1d 23 [2] 11 29 [2] 06 22 [2] 1d 6c [2] 20 }

  condition:
    any of them
}