rule TTP_XOR_MULT_DOSStub_0228 {
  strings:
    $key_0228 = { 56 40 [2] 22 58 [2] 65 5a [2] 22 4b [2] 6c 47 [2] 60 4d [2] 77 46 [2] 6c 08 [2] 51 }

  condition:
    any of them
}