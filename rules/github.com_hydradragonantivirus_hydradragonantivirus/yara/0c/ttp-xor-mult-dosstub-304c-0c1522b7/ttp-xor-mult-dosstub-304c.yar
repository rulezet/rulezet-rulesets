rule TTP_XOR_MULT_DOSStub_304c {
  strings:
    $key_304c = { 64 24 [2] 10 3c [2] 57 3e [2] 10 2f [2] 5e 23 [2] 52 29 [2] 45 22 [2] 5e 6c [2] 63 }

  condition:
    any of them
}