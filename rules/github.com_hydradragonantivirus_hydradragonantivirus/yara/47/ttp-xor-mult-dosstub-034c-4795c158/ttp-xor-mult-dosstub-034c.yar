rule TTP_XOR_MULT_DOSStub_034c {
  strings:
    $key_034c = { 57 24 [2] 23 3c [2] 64 3e [2] 23 2f [2] 6d 23 [2] 61 29 [2] 76 22 [2] 6d 6c [2] 50 }

  condition:
    any of them
}