rule TTP_XOR_MULT_DOSStub_156c {
  strings:
    $key_156c = { 41 04 [2] 35 1c [2] 72 1e [2] 35 0f [2] 7b 03 [2] 77 09 [2] 60 02 [2] 7b 4c [2] 46 }

  condition:
    any of them
}