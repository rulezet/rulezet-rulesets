rule TTP_XOR_MULT_DOSStub_3f47 {
  strings:
    $key_3f47 = { 6b 2f [2] 1f 37 [2] 58 35 [2] 1f 24 [2] 51 28 [2] 5d 22 [2] 4a 29 [2] 51 67 [2] 6c }

  condition:
    any of them
}