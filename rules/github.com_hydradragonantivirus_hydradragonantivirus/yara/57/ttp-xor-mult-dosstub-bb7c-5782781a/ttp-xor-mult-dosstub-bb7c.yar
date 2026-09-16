rule TTP_XOR_MULT_DOSStub_bb7c {
  strings:
    $key_bb7c = { ef 14 [2] 9b 0c [2] dc 0e [2] 9b 1f [2] d5 13 [2] d9 19 [2] ce 12 [2] d5 5c [2] e8 }

  condition:
    any of them
}