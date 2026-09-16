rule TTP_XOR_MULT_DOSStub_15e3 {
  strings:
    $key_15e3 = { 41 8b [2] 35 93 [2] 72 91 [2] 35 80 [2] 7b 8c [2] 77 86 [2] 60 8d [2] 7b c3 [2] 46 }

  condition:
    any of them
}