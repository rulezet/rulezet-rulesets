rule TTP_XOR_MULT_DOSStub_bb77 {
  strings:
    $key_bb77 = { ef 1f [2] 9b 07 [2] dc 05 [2] 9b 14 [2] d5 18 [2] d9 12 [2] ce 19 [2] d5 57 [2] e8 }

  condition:
    any of them
}