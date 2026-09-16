rule TTP_XOR_MULT_DOSStub_3638 {
  strings:
    $key_3638 = { 62 50 [2] 16 48 [2] 51 4a [2] 16 5b [2] 58 57 [2] 54 5d [2] 43 56 [2] 58 18 [2] 65 }

  condition:
    any of them
}