rule TTP_XOR_MULT_DOSStub_3466 {
  strings:
    $key_3466 = { 60 0e [2] 14 16 [2] 53 14 [2] 14 05 [2] 5a 09 [2] 56 03 [2] 41 08 [2] 5a 46 [2] 67 }

  condition:
    any of them
}