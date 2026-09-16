rule TTP_XOR_MULT_DOSStub_34f1 {
  strings:
    $key_34f1 = { 60 99 [2] 14 81 [2] 53 83 [2] 14 92 [2] 5a 9e [2] 56 94 [2] 41 9f [2] 5a d1 [2] 67 }

  condition:
    any of them
}