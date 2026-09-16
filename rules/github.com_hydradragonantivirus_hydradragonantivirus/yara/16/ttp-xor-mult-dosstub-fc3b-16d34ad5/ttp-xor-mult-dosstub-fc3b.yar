rule TTP_XOR_MULT_DOSStub_fc3b {
  strings:
    $key_fc3b = { a8 53 [2] dc 4b [2] 9b 49 [2] dc 58 [2] 92 54 [2] 9e 5e [2] 89 55 [2] 92 1b [2] af }

  condition:
    any of them
}