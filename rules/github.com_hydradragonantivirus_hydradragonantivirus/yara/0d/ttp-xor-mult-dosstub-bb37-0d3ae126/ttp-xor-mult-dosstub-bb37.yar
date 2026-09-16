rule TTP_XOR_MULT_DOSStub_bb37 {
  strings:
    $key_bb37 = { ef 5f [2] 9b 47 [2] dc 45 [2] 9b 54 [2] d5 58 [2] d9 52 [2] ce 59 [2] d5 17 [2] e8 }

  condition:
    any of them
}