rule TTP_XOR_MULT_DOSStub_bbf7 {
  strings:
    $key_bbf7 = { ef 9f [2] 9b 87 [2] dc 85 [2] 9b 94 [2] d5 98 [2] d9 92 [2] ce 99 [2] d5 d7 [2] e8 }

  condition:
    any of them
}