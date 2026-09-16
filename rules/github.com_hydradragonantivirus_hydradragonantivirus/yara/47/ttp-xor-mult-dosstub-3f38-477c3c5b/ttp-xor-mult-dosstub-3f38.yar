rule TTP_XOR_MULT_DOSStub_3f38 {
  strings:
    $key_3f38 = { 6b 50 [2] 1f 48 [2] 58 4a [2] 1f 5b [2] 51 57 [2] 5d 5d [2] 4a 56 [2] 51 18 [2] 6c }

  condition:
    any of them
}