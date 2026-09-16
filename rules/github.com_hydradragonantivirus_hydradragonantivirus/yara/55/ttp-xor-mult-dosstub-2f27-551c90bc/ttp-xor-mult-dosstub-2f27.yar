rule TTP_XOR_MULT_DOSStub_2f27 {
  strings:
    $key_2f27 = { 7b 4f [2] 0f 57 [2] 48 55 [2] 0f 44 [2] 41 48 [2] 4d 42 [2] 5a 49 [2] 41 07 [2] 7c }

  condition:
    any of them
}