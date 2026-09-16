rule TTP_XOR_MULT_DOSStub_3635 {
  strings:
    $key_3635 = { 62 5d [2] 16 45 [2] 51 47 [2] 16 56 [2] 58 5a [2] 54 50 [2] 43 5b [2] 58 15 [2] 65 }

  condition:
    any of them
}