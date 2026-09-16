rule TTP_XOR_MULT_DOSStub_c0ee {
  strings:
    $key_c0ee = { 94 86 [2] e0 9e [2] a7 9c [2] e0 8d [2] ae 81 [2] a2 8b [2] b5 80 [2] ae ce [2] 93 }

  condition:
    any of them
}