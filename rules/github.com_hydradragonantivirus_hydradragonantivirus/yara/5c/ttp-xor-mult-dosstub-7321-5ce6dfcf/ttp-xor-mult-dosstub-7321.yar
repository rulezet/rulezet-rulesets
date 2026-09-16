rule TTP_XOR_MULT_DOSStub_7321 {
  strings:
    $key_7321 = { 27 49 [2] 53 51 [2] 14 53 [2] 53 42 [2] 1d 4e [2] 11 44 [2] 06 4f [2] 1d 01 [2] 20 }

  condition:
    any of them
}