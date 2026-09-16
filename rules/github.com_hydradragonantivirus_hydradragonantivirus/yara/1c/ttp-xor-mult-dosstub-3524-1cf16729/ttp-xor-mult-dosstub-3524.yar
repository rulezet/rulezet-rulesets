rule TTP_XOR_MULT_DOSStub_3524 {
  strings:
    $key_3524 = { 61 4c [2] 15 54 [2] 52 56 [2] 15 47 [2] 5b 4b [2] 57 41 [2] 40 4a [2] 5b 04 [2] 66 }

  condition:
    any of them
}