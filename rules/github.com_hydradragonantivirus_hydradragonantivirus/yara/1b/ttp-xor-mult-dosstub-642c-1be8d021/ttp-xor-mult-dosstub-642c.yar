rule TTP_XOR_MULT_DOSStub_642c {
  strings:
    $key_642c = { 30 44 [2] 44 5c [2] 03 5e [2] 44 4f [2] 0a 43 [2] 06 49 [2] 11 42 [2] 0a 0c [2] 37 }

  condition:
    any of them
}