rule TTP_XOR_MULT_DOSStub_2ff7 {
  strings:
    $key_2ff7 = { 7b 9f [2] 0f 87 [2] 48 85 [2] 0f 94 [2] 41 98 [2] 4d 92 [2] 5a 99 [2] 41 d7 [2] 7c }

  condition:
    any of them
}