rule TTP_XOR_MULT_DOSStub_15e0 {
  strings:
    $key_15e0 = { 41 88 [2] 35 90 [2] 72 92 [2] 35 83 [2] 7b 8f [2] 77 85 [2] 60 8e [2] 7b c0 [2] 46 }

  condition:
    any of them
}