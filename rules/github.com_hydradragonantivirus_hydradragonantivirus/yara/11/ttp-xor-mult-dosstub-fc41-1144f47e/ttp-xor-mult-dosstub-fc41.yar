rule TTP_XOR_MULT_DOSStub_fc41 {
  strings:
    $key_fc41 = { a8 29 [2] dc 31 [2] 9b 33 [2] dc 22 [2] 92 2e [2] 9e 24 [2] 89 2f [2] 92 61 [2] af }

  condition:
    any of them
}