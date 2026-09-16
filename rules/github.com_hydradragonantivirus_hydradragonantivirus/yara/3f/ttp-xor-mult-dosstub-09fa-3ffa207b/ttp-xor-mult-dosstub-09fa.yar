rule TTP_XOR_MULT_DOSStub_09fa {
  strings:
    $key_09fa = { 5d 92 [2] 29 8a [2] 6e 88 [2] 29 99 [2] 67 95 [2] 6b 9f [2] 7c 94 [2] 67 da [2] 5a }

  condition:
    any of them
}