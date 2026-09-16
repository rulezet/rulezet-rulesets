rule TTP_XOR_MULT_DOSStub_fc01 {
  strings:
    $key_fc01 = { a8 69 [2] dc 71 [2] 9b 73 [2] dc 62 [2] 92 6e [2] 9e 64 [2] 89 6f [2] 92 21 [2] af }

  condition:
    any of them
}