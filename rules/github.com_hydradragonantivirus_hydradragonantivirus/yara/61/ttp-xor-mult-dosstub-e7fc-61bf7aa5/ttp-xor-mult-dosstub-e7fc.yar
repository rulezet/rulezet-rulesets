rule TTP_XOR_MULT_DOSStub_e7fc {
  strings:
    $key_e7fc = { b3 94 [2] c7 8c [2] 80 8e [2] c7 9f [2] 89 93 [2] 85 99 [2] 92 92 [2] 89 dc [2] b4 }

  condition:
    any of them
}