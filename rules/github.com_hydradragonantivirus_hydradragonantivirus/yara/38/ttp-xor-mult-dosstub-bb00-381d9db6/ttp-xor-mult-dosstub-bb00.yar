rule TTP_XOR_MULT_DOSStub_bb00 {
  strings:
    $key_bb00 = { ef 68 [2] 9b 70 [2] dc 72 [2] 9b 63 [2] d5 6f [2] d9 65 [2] ce 6e [2] d5 20 [2] e8 }

  condition:
    any of them
}