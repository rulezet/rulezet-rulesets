rule TTP_XOR_MULT_DOSStub_e8fc {
  strings:
    $key_e8fc = { bc 94 [2] c8 8c [2] 8f 8e [2] c8 9f [2] 86 93 [2] 8a 99 [2] 9d 92 [2] 86 dc [2] bb }

  condition:
    any of them
}