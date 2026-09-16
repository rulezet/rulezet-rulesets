rule TTP_XOR_MULT_DOSStub_15e2 {
  strings:
    $key_15e2 = { 41 8a [2] 35 92 [2] 72 90 [2] 35 81 [2] 7b 8d [2] 77 87 [2] 60 8c [2] 7b c2 [2] 46 }

  condition:
    any of them
}