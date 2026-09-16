rule TTP_XOR_MULT_DOSStub_bb17 {
  strings:
    $key_bb17 = { ef 7f [2] 9b 67 [2] dc 65 [2] 9b 74 [2] d5 78 [2] d9 72 [2] ce 79 [2] d5 37 [2] e8 }

  condition:
    any of them
}