rule TTP_XOR_MULT_DOSStub_0f47 {
  strings:
    $key_0f47 = { 5b 2f [2] 2f 37 [2] 68 35 [2] 2f 24 [2] 61 28 [2] 6d 22 [2] 7a 29 [2] 61 67 [2] 5c }

  condition:
    any of them
}