rule TTP_XOR_MULT_DOSStub_06e5 {
  strings:
    $key_06e5 = { 52 8d [2] 26 95 [2] 61 97 [2] 26 86 [2] 68 8a [2] 64 80 [2] 73 8b [2] 68 c5 [2] 55 }

  condition:
    any of them
}