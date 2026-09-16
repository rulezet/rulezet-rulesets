rule TTP_XOR_MULT_DOSStub_bb63 {
  strings:
    $key_bb63 = { ef 0b [2] 9b 13 [2] dc 11 [2] 9b 00 [2] d5 0c [2] d9 06 [2] ce 0d [2] d5 43 [2] e8 }

  condition:
    any of them
}