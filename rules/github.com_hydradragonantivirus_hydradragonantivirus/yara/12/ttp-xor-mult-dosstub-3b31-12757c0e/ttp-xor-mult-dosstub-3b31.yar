rule TTP_XOR_MULT_DOSStub_3b31 {
  strings:
    $key_3b31 = { 6f 59 [2] 1b 41 [2] 5c 43 [2] 1b 52 [2] 55 5e [2] 59 54 [2] 4e 5f [2] 55 11 [2] 68 }

  condition:
    any of them
}