rule TTP_XOR_MULT_DOSStub_bb66 {
  strings:
    $key_bb66 = { ef 0e [2] 9b 16 [2] dc 14 [2] 9b 05 [2] d5 09 [2] d9 03 [2] ce 08 [2] d5 46 [2] e8 }

  condition:
    any of them
}