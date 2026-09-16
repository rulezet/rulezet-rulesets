rule TTP_XOR_MULT_DOSStub_bb74 {
  strings:
    $key_bb74 = { ef 1c [2] 9b 04 [2] dc 06 [2] 9b 17 [2] d5 1b [2] d9 11 [2] ce 1a [2] d5 54 [2] e8 }

  condition:
    any of them
}