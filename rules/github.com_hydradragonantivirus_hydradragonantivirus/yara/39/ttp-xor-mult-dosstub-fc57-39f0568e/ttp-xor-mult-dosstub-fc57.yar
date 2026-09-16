rule TTP_XOR_MULT_DOSStub_fc57 {
  strings:
    $key_fc57 = { a8 3f [2] dc 27 [2] 9b 25 [2] dc 34 [2] 92 38 [2] 9e 32 [2] 89 39 [2] 92 77 [2] af }

  condition:
    any of them
}