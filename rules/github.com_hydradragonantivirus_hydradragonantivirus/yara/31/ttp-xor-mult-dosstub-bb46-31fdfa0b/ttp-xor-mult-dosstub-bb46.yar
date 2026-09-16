rule TTP_XOR_MULT_DOSStub_bb46 {
  strings:
    $key_bb46 = { ef 2e [2] 9b 36 [2] dc 34 [2] 9b 25 [2] d5 29 [2] d9 23 [2] ce 28 [2] d5 66 [2] e8 }

  condition:
    any of them
}