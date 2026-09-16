rule TTP_XOR_MULT_DOSStub_bbfa {
  strings:
    $key_bbfa = { ef 92 [2] 9b 8a [2] dc 88 [2] 9b 99 [2] d5 95 [2] d9 9f [2] ce 94 [2] d5 da [2] e8 }

  condition:
    any of them
}