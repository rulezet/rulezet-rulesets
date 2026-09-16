rule TTP_XOR_MULT_DOSStub_fab3 {
  strings:
    $key_fab3 = { ae db [2] da c3 [2] 9d c1 [2] da d0 [2] 94 dc [2] 98 d6 [2] 8f dd [2] 94 93 [2] a9 }

  condition:
    any of them
}