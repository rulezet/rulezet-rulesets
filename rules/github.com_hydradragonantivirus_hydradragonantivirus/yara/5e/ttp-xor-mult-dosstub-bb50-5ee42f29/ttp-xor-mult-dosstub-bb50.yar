rule TTP_XOR_MULT_DOSStub_bb50 {
  strings:
    $key_bb50 = { ef 38 [2] 9b 20 [2] dc 22 [2] 9b 33 [2] d5 3f [2] d9 35 [2] ce 3e [2] d5 70 [2] e8 }

  condition:
    any of them
}