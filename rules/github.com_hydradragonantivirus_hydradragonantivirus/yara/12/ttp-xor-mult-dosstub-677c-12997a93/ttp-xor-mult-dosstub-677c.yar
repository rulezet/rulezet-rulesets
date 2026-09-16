rule TTP_XOR_MULT_DOSStub_677c {
  strings:
    $key_677c = { 33 14 [2] 47 0c [2] 00 0e [2] 47 1f [2] 09 13 [2] 05 19 [2] 12 12 [2] 09 5c [2] 34 }

  condition:
    any of them
}