rule TTP_XOR_MULT_DOSStub_0f35 {
  strings:
    $key_0f35 = { 5b 5d [2] 2f 45 [2] 68 47 [2] 2f 56 [2] 61 5a [2] 6d 50 [2] 7a 5b [2] 61 15 [2] 5c }

  condition:
    any of them
}