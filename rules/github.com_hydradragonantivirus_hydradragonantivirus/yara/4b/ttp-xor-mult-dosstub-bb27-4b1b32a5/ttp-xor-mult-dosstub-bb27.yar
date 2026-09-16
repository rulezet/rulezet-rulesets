rule TTP_XOR_MULT_DOSStub_bb27 {
  strings:
    $key_bb27 = { ef 4f [2] 9b 57 [2] dc 55 [2] 9b 44 [2] d5 48 [2] d9 42 [2] ce 49 [2] d5 07 [2] e8 }

  condition:
    any of them
}