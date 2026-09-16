rule TTP_XOR_MULT_DOSStub_3431 {
  strings:
    $key_3431 = { 60 59 [2] 14 41 [2] 53 43 [2] 14 52 [2] 5a 5e [2] 56 54 [2] 41 5f [2] 5a 11 [2] 67 }

  condition:
    any of them
}