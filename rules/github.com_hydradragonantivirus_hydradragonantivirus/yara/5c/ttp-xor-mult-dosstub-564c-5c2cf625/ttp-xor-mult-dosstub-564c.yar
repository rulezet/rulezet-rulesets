rule TTP_XOR_MULT_DOSStub_564c {
  strings:
    $key_564c = { 02 24 [2] 76 3c [2] 31 3e [2] 76 2f [2] 38 23 [2] 34 29 [2] 23 22 [2] 38 6c [2] 05 }

  condition:
    any of them
}