rule TTP_XOR_MULT_DOSStub_e2fa {
  strings:
    $key_e2fa = { b6 92 [2] c2 8a [2] 85 88 [2] c2 99 [2] 8c 95 [2] 80 9f [2] 97 94 [2] 8c da [2] b1 }

  condition:
    any of them
}