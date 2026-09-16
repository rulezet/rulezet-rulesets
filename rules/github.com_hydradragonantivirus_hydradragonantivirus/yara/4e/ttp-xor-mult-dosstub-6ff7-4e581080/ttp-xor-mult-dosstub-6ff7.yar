rule TTP_XOR_MULT_DOSStub_6ff7 {
  strings:
    $key_6ff7 = { 3b 9f [2] 4f 87 [2] 08 85 [2] 4f 94 [2] 01 98 [2] 0d 92 [2] 1a 99 [2] 01 d7 [2] 3c }

  condition:
    any of them
}