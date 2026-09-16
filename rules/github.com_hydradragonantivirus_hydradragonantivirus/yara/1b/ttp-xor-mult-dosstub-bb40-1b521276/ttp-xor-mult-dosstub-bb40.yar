rule TTP_XOR_MULT_DOSStub_bb40 {
  strings:
    $key_bb40 = { ef 28 [2] 9b 30 [2] dc 32 [2] 9b 23 [2] d5 2f [2] d9 25 [2] ce 2e [2] d5 60 [2] e8 }

  condition:
    any of them
}