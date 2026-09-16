rule TTP_XOR_MULT_DOSStub_202c {
  strings:
    $key_202c = { 74 44 [2] 00 5c [2] 47 5e [2] 00 4f [2] 4e 43 [2] 42 49 [2] 55 42 [2] 4e 0c [2] 73 }

  condition:
    any of them
}