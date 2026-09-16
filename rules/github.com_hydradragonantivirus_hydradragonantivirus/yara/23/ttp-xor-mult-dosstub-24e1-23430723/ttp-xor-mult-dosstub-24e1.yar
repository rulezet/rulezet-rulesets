rule TTP_XOR_MULT_DOSStub_24e1 {
  strings:
    $key_24e1 = { 70 89 [2] 04 91 [2] 43 93 [2] 04 82 [2] 4a 8e [2] 46 84 [2] 51 8f [2] 4a c1 [2] 77 }

  condition:
    any of them
}