rule TTP_XOR_MULT_DOSStub_2fa6 {
  strings:
    $key_2fa6 = { 7b ce [2] 0f d6 [2] 48 d4 [2] 0f c5 [2] 41 c9 [2] 4d c3 [2] 5a c8 [2] 41 86 [2] 7c }

  condition:
    any of them
}