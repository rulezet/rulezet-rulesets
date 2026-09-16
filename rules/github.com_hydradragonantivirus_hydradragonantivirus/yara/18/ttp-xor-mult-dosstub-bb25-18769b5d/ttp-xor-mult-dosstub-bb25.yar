rule TTP_XOR_MULT_DOSStub_bb25 {
  strings:
    $key_bb25 = { ef 4d [2] 9b 55 [2] dc 57 [2] 9b 46 [2] d5 4a [2] d9 40 [2] ce 4b [2] d5 05 [2] e8 }

  condition:
    any of them
}