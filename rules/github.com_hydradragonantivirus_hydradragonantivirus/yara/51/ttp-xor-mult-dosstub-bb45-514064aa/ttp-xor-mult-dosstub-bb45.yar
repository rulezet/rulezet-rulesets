rule TTP_XOR_MULT_DOSStub_bb45 {
  strings:
    $key_bb45 = { ef 2d [2] 9b 35 [2] dc 37 [2] 9b 26 [2] d5 2a [2] d9 20 [2] ce 2b [2] d5 65 [2] e8 }

  condition:
    any of them
}