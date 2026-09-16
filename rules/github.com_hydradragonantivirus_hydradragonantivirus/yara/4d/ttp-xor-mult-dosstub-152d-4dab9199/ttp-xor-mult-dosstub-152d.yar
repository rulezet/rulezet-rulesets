rule TTP_XOR_MULT_DOSStub_152d {
  strings:
    $key_152d = { 41 45 [2] 35 5d [2] 72 5f [2] 35 4e [2] 7b 42 [2] 77 48 [2] 60 43 [2] 7b 0d [2] 46 }

  condition:
    any of them
}