rule TTP_XOR_MULT_DOSStub_e3fa {
  strings:
    $key_e3fa = { b7 92 [2] c3 8a [2] 84 88 [2] c3 99 [2] 8d 95 [2] 81 9f [2] 96 94 [2] 8d da [2] b0 }

  condition:
    any of them
}