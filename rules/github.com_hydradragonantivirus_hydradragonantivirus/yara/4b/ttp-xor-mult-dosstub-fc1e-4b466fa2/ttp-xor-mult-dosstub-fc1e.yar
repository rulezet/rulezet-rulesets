rule TTP_XOR_MULT_DOSStub_fc1e {
  strings:
    $key_fc1e = { a8 76 [2] dc 6e [2] 9b 6c [2] dc 7d [2] 92 71 [2] 9e 7b [2] 89 70 [2] 92 3e [2] af }

  condition:
    any of them
}