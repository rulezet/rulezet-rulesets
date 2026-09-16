rule TTP_XOR_MULT_DOSStub_32fc {
  strings:
    $key_32fc = { 66 94 [2] 12 8c [2] 55 8e [2] 12 9f [2] 5c 93 [2] 50 99 [2] 47 92 [2] 5c dc [2] 61 }

  condition:
    any of them
}