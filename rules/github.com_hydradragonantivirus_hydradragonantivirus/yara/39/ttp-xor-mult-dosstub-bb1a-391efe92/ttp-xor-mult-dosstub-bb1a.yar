rule TTP_XOR_MULT_DOSStub_bb1a {
  strings:
    $key_bb1a = { ef 72 [2] 9b 6a [2] dc 68 [2] 9b 79 [2] d5 75 [2] d9 7f [2] ce 74 [2] d5 3a [2] e8 }

  condition:
    any of them
}