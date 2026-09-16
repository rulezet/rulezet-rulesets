rule TTP_XOR_MULT_DOSStub_567c {
  strings:
    $key_567c = { 02 14 [2] 76 0c [2] 31 0e [2] 76 1f [2] 38 13 [2] 34 19 [2] 23 12 [2] 38 5c [2] 05 }

  condition:
    any of them
}