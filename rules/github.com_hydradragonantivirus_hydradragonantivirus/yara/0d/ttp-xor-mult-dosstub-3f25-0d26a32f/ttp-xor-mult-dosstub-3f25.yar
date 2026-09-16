rule TTP_XOR_MULT_DOSStub_3f25 {
  strings:
    $key_3f25 = { 6b 4d [2] 1f 55 [2] 58 57 [2] 1f 46 [2] 51 4a [2] 5d 40 [2] 4a 4b [2] 51 05 [2] 6c }

  condition:
    any of them
}