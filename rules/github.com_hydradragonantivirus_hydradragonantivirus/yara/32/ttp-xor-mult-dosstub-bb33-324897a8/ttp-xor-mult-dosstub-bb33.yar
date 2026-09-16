rule TTP_XOR_MULT_DOSStub_bb33 {
  strings:
    $key_bb33 = { ef 5b [2] 9b 43 [2] dc 41 [2] 9b 50 [2] d5 5c [2] d9 56 [2] ce 5d [2] d5 13 [2] e8 }

  condition:
    any of them
}