rule TTP_XOR_MULT_DOSStub_e7fa {
  strings:
    $key_e7fa = { b3 92 [2] c7 8a [2] 80 88 [2] c7 99 [2] 89 95 [2] 85 9f [2] 92 94 [2] 89 da [2] b4 }

  condition:
    any of them
}