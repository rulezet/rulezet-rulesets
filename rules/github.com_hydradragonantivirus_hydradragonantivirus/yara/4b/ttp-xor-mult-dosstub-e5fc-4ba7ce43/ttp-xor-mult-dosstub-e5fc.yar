rule TTP_XOR_MULT_DOSStub_e5fc {
  strings:
    $key_e5fc = { b1 94 [2] c5 8c [2] 82 8e [2] c5 9f [2] 8b 93 [2] 87 99 [2] 90 92 [2] 8b dc [2] b6 }

  condition:
    any of them
}