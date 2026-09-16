rule TTP_XOR_MULT_DOSStub_157c {
  strings:
    $key_157c = { 41 14 [2] 35 0c [2] 72 0e [2] 35 1f [2] 7b 13 [2] 77 19 [2] 60 12 [2] 7b 5c [2] 46 }

  condition:
    any of them
}