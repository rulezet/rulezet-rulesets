rule TTP_XOR_MULT_DOSStub_40fc {
  strings:
    $key_40fc = { 14 94 [2] 60 8c [2] 27 8e [2] 60 9f [2] 2e 93 [2] 22 99 [2] 35 92 [2] 2e dc [2] 13 }

  condition:
    any of them
}