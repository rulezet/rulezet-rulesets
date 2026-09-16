rule TTP_XOR_MULT_DOSStub_2fa9 {
  strings:
    $key_2fa9 = { 7b c1 [2] 0f d9 [2] 48 db [2] 0f ca [2] 41 c6 [2] 4d cc [2] 5a c7 [2] 41 89 [2] 7c }

  condition:
    any of them
}