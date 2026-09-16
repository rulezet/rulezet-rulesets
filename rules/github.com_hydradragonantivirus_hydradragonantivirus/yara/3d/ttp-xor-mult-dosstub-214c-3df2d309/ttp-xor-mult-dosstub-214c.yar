rule TTP_XOR_MULT_DOSStub_214c {
  strings:
    $key_214c = { 75 24 [2] 01 3c [2] 46 3e [2] 01 2f [2] 4f 23 [2] 43 29 [2] 54 22 [2] 4f 6c [2] 72 }

  condition:
    any of them
}