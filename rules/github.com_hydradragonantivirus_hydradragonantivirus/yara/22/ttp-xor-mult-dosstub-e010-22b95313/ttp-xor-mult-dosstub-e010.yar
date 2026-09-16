rule TTP_XOR_MULT_DOSStub_e010 {
  strings:
    $key_e010 = { b4 78 [2] c0 60 [2] 87 62 [2] c0 73 [2] 8e 7f [2] 82 75 [2] 95 7e [2] 8e 30 [2] b3 }

  condition:
    any of them
}