rule TTP_XOR_MULT_DOSStub_fafc {
  strings:
    $key_fafc = { ae 94 [2] da 8c [2] 9d 8e [2] da 9f [2] 94 93 [2] 98 99 [2] 8f 92 [2] 94 dc [2] a9 }

  condition:
    any of them
}