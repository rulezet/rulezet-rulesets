rule TTP_XOR_MULT_DOSStub_12fa {
  strings:
    $key_12fa = { 46 92 [2] 32 8a [2] 75 88 [2] 32 99 [2] 7c 95 [2] 70 9f [2] 67 94 [2] 7c da [2] 41 }

  condition:
    any of them
}