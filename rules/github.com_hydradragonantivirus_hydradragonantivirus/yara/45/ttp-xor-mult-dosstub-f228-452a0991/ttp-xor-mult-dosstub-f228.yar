rule TTP_XOR_MULT_DOSStub_f228 {
  strings:
    $key_f228 = { a6 40 [2] d2 58 [2] 95 5a [2] d2 4b [2] 9c 47 [2] 90 4d [2] 87 46 [2] 9c 08 [2] a1 }

  condition:
    any of them
}