rule TTP_XOR_MULT_DOSStub_2df1 {
  strings:
    $key_2df1 = { 79 99 [2] 0d 81 [2] 4a 83 [2] 0d 92 [2] 43 9e [2] 4f 94 [2] 58 9f [2] 43 d1 [2] 7e }

  condition:
    any of them
}