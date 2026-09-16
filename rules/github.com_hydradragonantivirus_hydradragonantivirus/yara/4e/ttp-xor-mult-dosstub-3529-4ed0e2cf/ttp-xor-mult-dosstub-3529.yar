rule TTP_XOR_MULT_DOSStub_3529 {
  strings:
    $key_3529 = { 61 41 [2] 15 59 [2] 52 5b [2] 15 4a [2] 5b 46 [2] 57 4c [2] 40 47 [2] 5b 09 [2] 66 }

  condition:
    any of them
}