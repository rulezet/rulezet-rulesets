rule TTP_XOR_MULT_DOSStub_0439 {
  strings:
    $key_0439 = { 50 51 [2] 24 49 [2] 63 4b [2] 24 5a [2] 6a 56 [2] 66 5c [2] 71 57 [2] 6a 19 [2] 57 }

  condition:
    any of them
}