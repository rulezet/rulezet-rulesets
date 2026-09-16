rule TTP_XOR_MULT_DOSStub_0931 {
  strings:
    $key_0931 = { 5d 59 [2] 29 41 [2] 6e 43 [2] 29 52 [2] 67 5e [2] 6b 54 [2] 7c 5f [2] 67 11 [2] 5a }

  condition:
    any of them
}