rule TTP_XOR_MULT_DOSStub_3f20 {
  strings:
    $key_3f20 = { 6b 48 [2] 1f 50 [2] 58 52 [2] 1f 43 [2] 51 4f [2] 5d 45 [2] 4a 4e [2] 51 00 [2] 6c }

  condition:
    any of them
}