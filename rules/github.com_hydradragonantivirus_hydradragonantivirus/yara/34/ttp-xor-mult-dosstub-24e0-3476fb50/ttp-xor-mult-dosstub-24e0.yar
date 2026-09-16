rule TTP_XOR_MULT_DOSStub_24e0 {
  strings:
    $key_24e0 = { 70 88 [2] 04 90 [2] 43 92 [2] 04 83 [2] 4a 8f [2] 46 85 [2] 51 8e [2] 4a c0 [2] 77 }

  condition:
    any of them
}