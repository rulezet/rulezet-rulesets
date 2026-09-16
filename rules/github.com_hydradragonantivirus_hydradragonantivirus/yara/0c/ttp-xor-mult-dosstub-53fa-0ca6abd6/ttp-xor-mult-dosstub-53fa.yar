rule TTP_XOR_MULT_DOSStub_53fa {
  strings:
    $key_53fa = { 07 92 [2] 73 8a [2] 34 88 [2] 73 99 [2] 3d 95 [2] 31 9f [2] 26 94 [2] 3d da [2] 00 }

  condition:
    any of them
}