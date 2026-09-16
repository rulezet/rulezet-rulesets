rule TTP_XOR_MULT_DOSStub_bb24 {
  strings:
    $key_bb24 = { ef 4c [2] 9b 54 [2] dc 56 [2] 9b 47 [2] d5 4b [2] d9 41 [2] ce 4a [2] d5 04 [2] e8 }

  condition:
    any of them
}