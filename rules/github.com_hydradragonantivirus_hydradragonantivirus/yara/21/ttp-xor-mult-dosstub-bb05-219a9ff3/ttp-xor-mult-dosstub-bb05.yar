rule TTP_XOR_MULT_DOSStub_bb05 {
  strings:
    $key_bb05 = { ef 6d [2] 9b 75 [2] dc 77 [2] 9b 66 [2] d5 6a [2] d9 60 [2] ce 6b [2] d5 25 [2] e8 }

  condition:
    any of them
}