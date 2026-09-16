rule TTP_XOR_MULT_DOSStub_bb7b {
  strings:
    $key_bb7b = { ef 13 [2] 9b 0b [2] dc 09 [2] 9b 18 [2] d5 14 [2] d9 1e [2] ce 15 [2] d5 5b [2] e8 }

  condition:
    any of them
}