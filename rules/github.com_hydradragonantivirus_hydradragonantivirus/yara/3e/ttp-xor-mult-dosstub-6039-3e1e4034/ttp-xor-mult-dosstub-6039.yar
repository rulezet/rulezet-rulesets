rule TTP_XOR_MULT_DOSStub_6039 {
  strings:
    $key_6039 = { 34 51 [2] 40 49 [2] 07 4b [2] 40 5a [2] 0e 56 [2] 02 5c [2] 15 57 [2] 0e 19 [2] 33 }

  condition:
    any of them
}