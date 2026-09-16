rule TTP_XOR_MULT_DOSStub_01fc {
  strings:
    $key_01fc = { 55 94 [2] 21 8c [2] 66 8e [2] 21 9f [2] 6f 93 [2] 63 99 [2] 74 92 [2] 6f dc [2] 52 }

  condition:
    any of them
}