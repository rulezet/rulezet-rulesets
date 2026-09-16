rule TTP_XOR_MULT_DOSStub_6db7 {
  strings:
    $key_6db7 = { 39 df [2] 4d c7 [2] 0a c5 [2] 4d d4 [2] 03 d8 [2] 0f d2 [2] 18 d9 [2] 03 97 [2] 3e }

  condition:
    any of them
}