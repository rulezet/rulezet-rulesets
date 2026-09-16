rule TTP_XOR_MULT_DOSStub_34f7 {
  strings:
    $key_34f7 = { 60 9f [2] 14 87 [2] 53 85 [2] 14 94 [2] 5a 98 [2] 56 92 [2] 41 99 [2] 5a d7 [2] 67 }

  condition:
    any of them
}