rule TTP_XOR_MULT_DOSStub_0f74 {
  strings:
    $key_0f74 = { 5b 1c [2] 2f 04 [2] 68 06 [2] 2f 17 [2] 61 1b [2] 6d 11 [2] 7a 1a [2] 61 54 [2] 5c }

  condition:
    any of them
}