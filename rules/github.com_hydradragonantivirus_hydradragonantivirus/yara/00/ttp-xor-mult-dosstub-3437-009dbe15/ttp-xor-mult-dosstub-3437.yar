rule TTP_XOR_MULT_DOSStub_3437 {
  strings:
    $key_3437 = { 60 5f [2] 14 47 [2] 53 45 [2] 14 54 [2] 5a 58 [2] 56 52 [2] 41 59 [2] 5a 17 [2] 67 }

  condition:
    any of them
}