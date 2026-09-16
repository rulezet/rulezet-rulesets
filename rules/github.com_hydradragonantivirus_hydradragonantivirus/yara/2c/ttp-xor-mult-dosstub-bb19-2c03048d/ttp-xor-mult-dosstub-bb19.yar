rule TTP_XOR_MULT_DOSStub_bb19 {
  strings:
    $key_bb19 = { ef 71 [2] 9b 69 [2] dc 6b [2] 9b 7a [2] d5 76 [2] d9 7c [2] ce 77 [2] d5 39 [2] e8 }

  condition:
    any of them
}