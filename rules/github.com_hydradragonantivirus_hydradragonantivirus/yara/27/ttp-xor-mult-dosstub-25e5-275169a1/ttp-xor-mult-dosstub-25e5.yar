rule TTP_XOR_MULT_DOSStub_25e5 {
  strings:
    $key_25e5 = { 71 8d [2] 05 95 [2] 42 97 [2] 05 86 [2] 4b 8a [2] 47 80 [2] 50 8b [2] 4b c5 [2] 76 }

  condition:
    any of them
}