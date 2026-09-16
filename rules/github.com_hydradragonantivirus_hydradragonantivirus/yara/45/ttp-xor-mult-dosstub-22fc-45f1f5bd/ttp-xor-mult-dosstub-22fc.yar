rule TTP_XOR_MULT_DOSStub_22fc {
  strings:
    $key_22fc = { 76 94 [2] 02 8c [2] 45 8e [2] 02 9f [2] 4c 93 [2] 40 99 [2] 57 92 [2] 4c dc [2] 71 }

  condition:
    any of them
}