rule TTP_XOR_MULT_DOSStub_4a4c {
  strings:
    $key_4a4c = { 1e 24 [2] 6a 3c [2] 2d 3e [2] 6a 2f [2] 24 23 [2] 28 29 [2] 3f 22 [2] 24 6c [2] 19 }

  condition:
    any of them
}