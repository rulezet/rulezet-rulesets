rule TTP_XOR_MULT_DOSStub_02fc {
  strings:
    $key_02fc = { 56 94 [2] 22 8c [2] 65 8e [2] 22 9f [2] 6c 93 [2] 60 99 [2] 77 92 [2] 6c dc [2] 51 }

  condition:
    any of them
}