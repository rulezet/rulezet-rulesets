rule TTP_XOR_MULT_DOSStub_bb28 {
  strings:
    $key_bb28 = { ef 40 [2] 9b 58 [2] dc 5a [2] 9b 4b [2] d5 47 [2] d9 4d [2] ce 46 [2] d5 08 [2] e8 }

  condition:
    any of them
}