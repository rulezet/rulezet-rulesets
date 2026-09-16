rule TTP_XOR_MULT_DOSStub_fc5c {
  strings:
    $key_fc5c = { a8 34 [2] dc 2c [2] 9b 2e [2] dc 3f [2] 92 33 [2] 9e 39 [2] 89 32 [2] 92 7c [2] af }

  condition:
    any of them
}