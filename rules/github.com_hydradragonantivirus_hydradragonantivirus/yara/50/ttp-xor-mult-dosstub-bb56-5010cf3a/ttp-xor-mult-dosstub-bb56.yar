rule TTP_XOR_MULT_DOSStub_bb56 {
  strings:
    $key_bb56 = { ef 3e [2] 9b 26 [2] dc 24 [2] 9b 35 [2] d5 39 [2] d9 33 [2] ce 38 [2] d5 76 [2] e8 }

  condition:
    any of them
}