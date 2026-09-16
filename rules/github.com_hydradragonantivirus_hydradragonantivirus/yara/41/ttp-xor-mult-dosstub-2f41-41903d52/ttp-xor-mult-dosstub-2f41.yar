rule TTP_XOR_MULT_DOSStub_2f41 {
  strings:
    $key_2f41 = { 7b 29 [2] 0f 31 [2] 48 33 [2] 0f 22 [2] 41 2e [2] 4d 24 [2] 5a 2f [2] 41 61 [2] 7c }

  condition:
    any of them
}