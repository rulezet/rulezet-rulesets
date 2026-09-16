rule TTP_XOR_MULT_DOSStub_0f69 {
  strings:
    $key_0f69 = { 5b 01 [2] 2f 19 [2] 68 1b [2] 2f 0a [2] 61 06 [2] 6d 0c [2] 7a 07 [2] 61 49 [2] 5c }

  condition:
    any of them
}