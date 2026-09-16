rule TTP_XOR_MULT_DOSStub_3460 {
  strings:
    $key_3460 = { 60 08 [2] 14 10 [2] 53 12 [2] 14 03 [2] 5a 0f [2] 56 05 [2] 41 0e [2] 5a 40 [2] 67 }

  condition:
    any of them
}