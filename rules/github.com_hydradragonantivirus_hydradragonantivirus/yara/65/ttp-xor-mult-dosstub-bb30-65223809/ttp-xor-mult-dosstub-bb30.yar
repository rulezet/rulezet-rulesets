rule TTP_XOR_MULT_DOSStub_bb30 {
  strings:
    $key_bb30 = { ef 58 [2] 9b 40 [2] dc 42 [2] 9b 53 [2] d5 5f [2] d9 55 [2] ce 5e [2] d5 10 [2] e8 }

  condition:
    any of them
}