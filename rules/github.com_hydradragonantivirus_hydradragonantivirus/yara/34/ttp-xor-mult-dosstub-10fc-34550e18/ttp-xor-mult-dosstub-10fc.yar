rule TTP_XOR_MULT_DOSStub_10fc {
  strings:
    $key_10fc = { 44 94 [2] 30 8c [2] 77 8e [2] 30 9f [2] 7e 93 [2] 72 99 [2] 65 92 [2] 7e dc [2] 43 }

  condition:
    any of them
}