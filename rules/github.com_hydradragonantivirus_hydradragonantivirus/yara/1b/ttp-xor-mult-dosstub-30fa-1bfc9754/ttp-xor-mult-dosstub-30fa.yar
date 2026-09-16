rule TTP_XOR_MULT_DOSStub_30fa {
  strings:
    $key_30fa = { 64 92 [2] 10 8a [2] 57 88 [2] 10 99 [2] 5e 95 [2] 52 9f [2] 45 94 [2] 5e da [2] 63 }

  condition:
    any of them
}