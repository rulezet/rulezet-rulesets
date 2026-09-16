rule TTP_XOR_MULT_DOSStub_fc3e {
  strings:
    $key_fc3e = { a8 56 [2] dc 4e [2] 9b 4c [2] dc 5d [2] 92 51 [2] 9e 5b [2] 89 50 [2] 92 1e [2] af }

  condition:
    any of them
}