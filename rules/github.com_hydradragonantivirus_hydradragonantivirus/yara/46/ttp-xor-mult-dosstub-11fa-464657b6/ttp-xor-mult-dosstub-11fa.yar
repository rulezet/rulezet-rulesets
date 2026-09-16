rule TTP_XOR_MULT_DOSStub_11fa {
  strings:
    $key_11fa = { 45 92 [2] 31 8a [2] 76 88 [2] 31 99 [2] 7f 95 [2] 73 9f [2] 64 94 [2] 7f da [2] 42 }

  condition:
    any of them
}