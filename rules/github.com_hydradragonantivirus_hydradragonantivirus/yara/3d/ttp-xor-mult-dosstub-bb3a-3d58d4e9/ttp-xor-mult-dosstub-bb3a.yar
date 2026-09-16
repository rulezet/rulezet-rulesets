rule TTP_XOR_MULT_DOSStub_bb3a {
  strings:
    $key_bb3a = { ef 52 [2] 9b 4a [2] dc 48 [2] 9b 59 [2] d5 55 [2] d9 5f [2] ce 54 [2] d5 1a [2] e8 }

  condition:
    any of them
}