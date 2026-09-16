rule TTP_XOR_MULT_DOSStub_bbf1 {
  strings:
    $key_bbf1 = { ef 99 [2] 9b 81 [2] dc 83 [2] 9b 92 [2] d5 9e [2] d9 94 [2] ce 9f [2] d5 d1 [2] e8 }

  condition:
    any of them
}