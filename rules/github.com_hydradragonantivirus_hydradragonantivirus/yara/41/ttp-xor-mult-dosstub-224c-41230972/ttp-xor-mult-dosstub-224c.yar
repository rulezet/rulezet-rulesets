rule TTP_XOR_MULT_DOSStub_224c {
  strings:
    $key_224c = { 76 24 [2] 02 3c [2] 45 3e [2] 02 2f [2] 4c 23 [2] 40 29 [2] 57 22 [2] 4c 6c [2] 71 }

  condition:
    any of them
}