rule TTP_XOR_MULT_DOSStub_5616 {
  strings:
    $key_5616 = { 02 7e [2] 76 66 [2] 31 64 [2] 76 75 [2] 38 79 [2] 34 73 [2] 23 78 [2] 38 36 [2] 05 }

  condition:
    any of them
}