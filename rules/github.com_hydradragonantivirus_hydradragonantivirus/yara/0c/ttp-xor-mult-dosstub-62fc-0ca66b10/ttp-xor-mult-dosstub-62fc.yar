rule TTP_XOR_MULT_DOSStub_62fc {
  strings:
    $key_62fc = { 36 94 [2] 42 8c [2] 05 8e [2] 42 9f [2] 0c 93 [2] 00 99 [2] 17 92 [2] 0c dc [2] 31 }

  condition:
    any of them
}