rule TTP_XOR_MULT_DOSStub_bb22 {
  strings:
    $key_bb22 = { ef 4a [2] 9b 52 [2] dc 50 [2] 9b 41 [2] d5 4d [2] d9 47 [2] ce 4c [2] d5 02 [2] e8 }

  condition:
    any of them
}