rule TTP_XOR_MULT_DOSStub_51fc {
  strings:
    $key_51fc = { 05 94 [2] 71 8c [2] 36 8e [2] 71 9f [2] 3f 93 [2] 33 99 [2] 24 92 [2] 3f dc [2] 02 }

  condition:
    any of them
}