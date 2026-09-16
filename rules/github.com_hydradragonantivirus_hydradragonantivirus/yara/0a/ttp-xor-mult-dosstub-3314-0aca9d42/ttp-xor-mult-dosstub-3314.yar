rule TTP_XOR_MULT_DOSStub_3314 {
  strings:
    $key_3314 = { 67 7c [2] 13 64 [2] 54 66 [2] 13 77 [2] 5d 7b [2] 51 71 [2] 46 7a [2] 5d 34 [2] 60 }

  condition:
    any of them
}