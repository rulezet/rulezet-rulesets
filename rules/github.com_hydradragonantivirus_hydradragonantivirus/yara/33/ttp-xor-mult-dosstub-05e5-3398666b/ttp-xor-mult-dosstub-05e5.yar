rule TTP_XOR_MULT_DOSStub_05e5 {
  strings:
    $key_05e5 = { 51 8d [2] 25 95 [2] 62 97 [2] 25 86 [2] 6b 8a [2] 67 80 [2] 70 8b [2] 6b c5 [2] 56 }

  condition:
    any of them
}