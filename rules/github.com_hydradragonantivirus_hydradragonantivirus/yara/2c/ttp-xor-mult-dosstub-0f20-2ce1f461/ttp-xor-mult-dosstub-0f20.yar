rule TTP_XOR_MULT_DOSStub_0f20 {
  strings:
    $key_0f20 = { 5b 48 [2] 2f 50 [2] 68 52 [2] 2f 43 [2] 61 4f [2] 6d 45 [2] 7a 4e [2] 61 00 [2] 5c }

  condition:
    any of them
}