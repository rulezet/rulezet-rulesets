rule TTP_XOR_MULT_DOSStub_3535 {
  strings:
    $key_3535 = { 61 5d [2] 15 45 [2] 52 47 [2] 15 56 [2] 5b 5a [2] 57 50 [2] 40 5b [2] 5b 15 [2] 66 }

  condition:
    any of them
}