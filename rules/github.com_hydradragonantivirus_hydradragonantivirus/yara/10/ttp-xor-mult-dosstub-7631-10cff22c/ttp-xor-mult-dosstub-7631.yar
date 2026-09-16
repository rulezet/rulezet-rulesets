rule TTP_XOR_MULT_DOSStub_7631 {
  strings:
    $key_7631 = { 22 59 [2] 56 41 [2] 11 43 [2] 56 52 [2] 18 5e [2] 14 54 [2] 03 5f [2] 18 11 [2] 25 }

  condition:
    any of them
}