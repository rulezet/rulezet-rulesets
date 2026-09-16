rule TTP_XOR_MULT_DOSStub_452d {
  strings:
    $key_452d = { 11 45 [2] 65 5d [2] 22 5f [2] 65 4e [2] 2b 42 [2] 27 48 [2] 30 43 [2] 2b 0d [2] 16 }

  condition:
    any of them
}