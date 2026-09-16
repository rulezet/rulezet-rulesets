rule TTP_XOR_MULT_DOSStub_221e {
  strings:
    $key_221e = { 76 76 [2] 02 6e [2] 45 6c [2] 02 7d [2] 4c 71 [2] 40 7b [2] 57 70 [2] 4c 3e [2] 71 }

  condition:
    any of them
}