rule TTP_XOR_MULT_DOSStub_247c {
  strings:
    $key_247c = { 70 14 [2] 04 0c [2] 43 0e [2] 04 1f [2] 4a 13 [2] 46 19 [2] 51 12 [2] 4a 5c [2] 77 }

  condition:
    any of them
}