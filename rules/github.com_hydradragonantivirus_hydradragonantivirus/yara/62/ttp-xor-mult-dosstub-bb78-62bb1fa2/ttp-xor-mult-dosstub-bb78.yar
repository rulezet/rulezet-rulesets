rule TTP_XOR_MULT_DOSStub_bb78 {
  strings:
    $key_bb78 = { ef 10 [2] 9b 08 [2] dc 0a [2] 9b 1b [2] d5 17 [2] d9 1d [2] ce 16 [2] d5 58 [2] e8 }

  condition:
    any of them
}