rule TTP_XOR_MULT_DOSStub_0f33 {
  strings:
    $key_0f33 = { 5b 5b [2] 2f 43 [2] 68 41 [2] 2f 50 [2] 61 5c [2] 6d 56 [2] 7a 5d [2] 61 13 [2] 5c }

  condition:
    any of them
}