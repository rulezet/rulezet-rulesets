rule TTP_XOR_MULT_DOSStub_2f20 {
  strings:
    $key_2f20 = { 7b 48 [2] 0f 50 [2] 48 52 [2] 0f 43 [2] 41 4f [2] 4d 45 [2] 5a 4e [2] 41 00 [2] 7c }

  condition:
    any of them
}