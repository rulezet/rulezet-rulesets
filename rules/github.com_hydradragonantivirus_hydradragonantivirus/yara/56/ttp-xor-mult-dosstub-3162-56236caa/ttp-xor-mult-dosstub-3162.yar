rule TTP_XOR_MULT_DOSStub_3162 {
  strings:
    $key_3162 = { 65 0a [2] 11 12 [2] 56 10 [2] 11 01 [2] 5f 0d [2] 53 07 [2] 44 0c [2] 5f 42 [2] 62 }

  condition:
    any of them
}