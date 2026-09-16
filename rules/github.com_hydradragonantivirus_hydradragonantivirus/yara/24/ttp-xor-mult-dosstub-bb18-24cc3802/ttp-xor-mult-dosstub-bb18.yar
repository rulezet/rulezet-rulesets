rule TTP_XOR_MULT_DOSStub_bb18 {
  strings:
    $key_bb18 = { ef 70 [2] 9b 68 [2] dc 6a [2] 9b 7b [2] d5 77 [2] d9 7d [2] ce 76 [2] d5 38 [2] e8 }

  condition:
    any of them
}