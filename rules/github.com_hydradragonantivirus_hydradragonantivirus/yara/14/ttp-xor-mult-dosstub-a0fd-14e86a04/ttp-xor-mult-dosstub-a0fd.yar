rule TTP_XOR_MULT_DOSStub_a0fd {
  strings:
    $key_a0fd = { f4 95 [2] 80 8d [2] c7 8f [2] 80 9e [2] ce 92 [2] c2 98 [2] d5 93 [2] ce dd [2] f3 }

  condition:
    any of them
}