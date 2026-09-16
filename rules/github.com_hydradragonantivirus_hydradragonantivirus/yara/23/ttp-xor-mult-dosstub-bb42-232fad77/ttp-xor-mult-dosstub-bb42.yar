rule TTP_XOR_MULT_DOSStub_bb42 {
  strings:
    $key_bb42 = { ef 2a [2] 9b 32 [2] dc 30 [2] 9b 21 [2] d5 2d [2] d9 27 [2] ce 2c [2] d5 62 [2] e8 }

  condition:
    any of them
}