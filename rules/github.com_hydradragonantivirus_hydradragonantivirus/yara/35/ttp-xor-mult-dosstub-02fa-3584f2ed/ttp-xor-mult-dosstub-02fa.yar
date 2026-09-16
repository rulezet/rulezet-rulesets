rule TTP_XOR_MULT_DOSStub_02fa {
  strings:
    $key_02fa = { 56 92 [2] 22 8a [2] 65 88 [2] 22 99 [2] 6c 95 [2] 60 9f [2] 77 94 [2] 6c da [2] 51 }

  condition:
    any of them
}