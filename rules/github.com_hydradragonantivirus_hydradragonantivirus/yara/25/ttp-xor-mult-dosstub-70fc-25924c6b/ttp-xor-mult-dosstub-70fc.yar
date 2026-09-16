rule TTP_XOR_MULT_DOSStub_70fc {
  strings:
    $key_70fc = { 24 94 [2] 50 8c [2] 17 8e [2] 50 9f [2] 1e 93 [2] 12 99 [2] 05 92 [2] 1e dc [2] 23 }

  condition:
    any of them
}