rule TTP_XOR_MULT_DOSStub_bb71 {
  strings:
    $key_bb71 = { ef 19 [2] 9b 01 [2] dc 03 [2] 9b 12 [2] d5 1e [2] d9 14 [2] ce 1f [2] d5 51 [2] e8 }

  condition:
    any of them
}