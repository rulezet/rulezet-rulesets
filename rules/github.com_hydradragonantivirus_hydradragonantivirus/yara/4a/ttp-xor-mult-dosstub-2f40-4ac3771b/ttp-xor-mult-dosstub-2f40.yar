rule TTP_XOR_MULT_DOSStub_2f40 {
  strings:
    $key_2f40 = { 7b 28 [2] 0f 30 [2] 48 32 [2] 0f 23 [2] 41 2f [2] 4d 25 [2] 5a 2e [2] 41 60 [2] 7c }

  condition:
    any of them
}