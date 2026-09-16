rule TTP_XOR_MULT_DOSStub_511c {
  strings:
    $key_511c = { 05 74 [2] 71 6c [2] 36 6e [2] 71 7f [2] 3f 73 [2] 33 79 [2] 24 72 [2] 3f 3c [2] 02 }

  condition:
    any of them
}