rule TTP_XOR_MULT_DOSStub_bb54 {
  strings:
    $key_bb54 = { ef 3c [2] 9b 24 [2] dc 26 [2] 9b 37 [2] d5 3b [2] d9 31 [2] ce 3a [2] d5 74 [2] e8 }

  condition:
    any of them
}