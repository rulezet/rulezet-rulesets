rule TTP_XOR_MULT_DOSStub_334c {
  strings:
    $key_334c = { 67 24 [2] 13 3c [2] 54 3e [2] 13 2f [2] 5d 23 [2] 51 29 [2] 46 22 [2] 5d 6c [2] 60 }

  condition:
    any of them
}