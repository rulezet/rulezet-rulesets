rule TTP_XOR_MULT_DOSStub_0b31 {
  strings:
    $key_0b31 = { 5f 59 [2] 2b 41 [2] 6c 43 [2] 2b 52 [2] 65 5e [2] 69 54 [2] 7e 5f [2] 65 11 [2] 58 }

  condition:
    any of them
}