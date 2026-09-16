rule TTP_XOR_MULT_DOSStub_374c {
  strings:
    $key_374c = { 63 24 [2] 17 3c [2] 50 3e [2] 17 2f [2] 59 23 [2] 55 29 [2] 42 22 [2] 59 6c [2] 64 }

  condition:
    any of them
}