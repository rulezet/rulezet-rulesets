rule TTP_XOR_MULT_DOSStub_bb43 {
  strings:
    $key_bb43 = { ef 2b [2] 9b 33 [2] dc 31 [2] 9b 20 [2] d5 2c [2] d9 26 [2] ce 2d [2] d5 63 [2] e8 }

  condition:
    any of them
}