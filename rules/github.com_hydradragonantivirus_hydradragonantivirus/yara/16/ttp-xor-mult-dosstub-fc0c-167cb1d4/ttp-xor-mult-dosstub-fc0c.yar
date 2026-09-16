rule TTP_XOR_MULT_DOSStub_fc0c {
  strings:
    $key_fc0c = { a8 64 [2] dc 7c [2] 9b 7e [2] dc 6f [2] 92 63 [2] 9e 69 [2] 89 62 [2] 92 2c [2] af }

  condition:
    any of them
}