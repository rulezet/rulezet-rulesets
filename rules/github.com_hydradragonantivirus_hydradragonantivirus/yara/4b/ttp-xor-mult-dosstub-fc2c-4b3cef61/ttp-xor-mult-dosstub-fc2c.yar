rule TTP_XOR_MULT_DOSStub_fc2c {
  strings:
    $key_fc2c = { a8 44 [2] dc 5c [2] 9b 5e [2] dc 4f [2] 92 43 [2] 9e 49 [2] 89 42 [2] 92 0c [2] af }

  condition:
    any of them
}