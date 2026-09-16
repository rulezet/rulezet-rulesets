rule TTP_XOR_MULT_DOSStub_bb62 {
  strings:
    $key_bb62 = { ef 0a [2] 9b 12 [2] dc 10 [2] 9b 01 [2] d5 0d [2] d9 07 [2] ce 0c [2] d5 42 [2] e8 }

  condition:
    any of them
}