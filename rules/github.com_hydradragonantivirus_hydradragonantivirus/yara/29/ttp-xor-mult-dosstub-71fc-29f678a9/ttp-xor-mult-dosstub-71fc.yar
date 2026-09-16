rule TTP_XOR_MULT_DOSStub_71fc {
  strings:
    $key_71fc = { 25 94 [2] 51 8c [2] 16 8e [2] 51 9f [2] 1f 93 [2] 13 99 [2] 04 92 [2] 1f dc [2] 22 }

  condition:
    any of them
}