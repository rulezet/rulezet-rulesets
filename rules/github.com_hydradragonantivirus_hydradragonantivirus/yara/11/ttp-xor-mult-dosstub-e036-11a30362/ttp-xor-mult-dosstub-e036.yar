rule TTP_XOR_MULT_DOSStub_e036 {
  strings:
    $key_e036 = { b4 5e [2] c0 46 [2] 87 44 [2] c0 55 [2] 8e 59 [2] 82 53 [2] 95 58 [2] 8e 16 [2] b3 }

  condition:
    any of them
}