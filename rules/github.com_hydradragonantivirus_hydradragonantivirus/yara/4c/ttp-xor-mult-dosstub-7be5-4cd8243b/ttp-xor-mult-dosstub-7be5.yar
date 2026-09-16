rule TTP_XOR_MULT_DOSStub_7be5 {
  strings:
    $key_7be5 = { 2f 8d [2] 5b 95 [2] 1c 97 [2] 5b 86 [2] 15 8a [2] 19 80 [2] 0e 8b [2] 15 c5 [2] 28 }

  condition:
    any of them
}