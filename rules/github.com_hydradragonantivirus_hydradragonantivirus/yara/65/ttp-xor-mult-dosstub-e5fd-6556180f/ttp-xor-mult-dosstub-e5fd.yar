rule TTP_XOR_MULT_DOSStub_e5fd {
  strings:
    $key_e5fd = { b1 95 [2] c5 8d [2] 82 8f [2] c5 9e [2] 8b 92 [2] 87 98 [2] 90 93 [2] 8b dd [2] b6 }

  condition:
    any of them
}