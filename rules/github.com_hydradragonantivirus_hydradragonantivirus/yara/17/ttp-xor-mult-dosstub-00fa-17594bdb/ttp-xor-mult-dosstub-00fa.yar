rule TTP_XOR_MULT_DOSStub_00fa {
  strings:
    $key_00fa = { 54 92 [2] 20 8a [2] 67 88 [2] 20 99 [2] 6e 95 [2] 62 9f [2] 75 94 [2] 6e da [2] 53 }

  condition:
    any of them
}