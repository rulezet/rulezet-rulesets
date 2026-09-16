rule TTP_XOR_MULT_DOSStub_23fa {
  strings:
    $key_23fa = { 77 92 [2] 03 8a [2] 44 88 [2] 03 99 [2] 4d 95 [2] 41 9f [2] 56 94 [2] 4d da [2] 70 }

  condition:
    any of them
}