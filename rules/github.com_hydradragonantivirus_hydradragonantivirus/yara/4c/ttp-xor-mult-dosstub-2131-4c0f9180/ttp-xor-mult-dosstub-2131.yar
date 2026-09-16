rule TTP_XOR_MULT_DOSStub_2131 {
  strings:
    $key_2131 = { 75 59 [2] 01 41 [2] 46 43 [2] 01 52 [2] 4f 5e [2] 43 54 [2] 54 5f [2] 4f 11 [2] 72 }

  condition:
    any of them
}