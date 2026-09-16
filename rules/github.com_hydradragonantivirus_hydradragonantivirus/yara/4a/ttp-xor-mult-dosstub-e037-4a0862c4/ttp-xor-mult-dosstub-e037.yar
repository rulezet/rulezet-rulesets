rule TTP_XOR_MULT_DOSStub_e037 {
  strings:
    $key_e037 = { b4 5f [2] c0 47 [2] 87 45 [2] c0 54 [2] 8e 58 [2] 82 52 [2] 95 59 [2] 8e 17 [2] b3 }

  condition:
    any of them
}