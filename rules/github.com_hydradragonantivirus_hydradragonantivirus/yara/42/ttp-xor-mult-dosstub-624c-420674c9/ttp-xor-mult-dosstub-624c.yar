rule TTP_XOR_MULT_DOSStub_624c {
  strings:
    $key_624c = { 36 24 [2] 42 3c [2] 05 3e [2] 42 2f [2] 0c 23 [2] 00 29 [2] 17 22 [2] 0c 6c [2] 31 }

  condition:
    any of them
}