rule TTP_XOR_MULT_DOSStub_19fa {
  strings:
    $key_19fa = { 4d 92 [2] 39 8a [2] 7e 88 [2] 39 99 [2] 77 95 [2] 7b 9f [2] 6c 94 [2] 77 da [2] 4a }

  condition:
    any of them
}