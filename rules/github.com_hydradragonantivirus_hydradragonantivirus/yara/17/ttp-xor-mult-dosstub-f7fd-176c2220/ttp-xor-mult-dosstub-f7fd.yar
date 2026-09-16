rule TTP_XOR_MULT_DOSStub_f7fd {
  strings:
    $key_f7fd = { a3 95 [2] d7 8d [2] 90 8f [2] d7 9e [2] 99 92 [2] 95 98 [2] 82 93 [2] 99 dd [2] a4 }

  condition:
    any of them
}