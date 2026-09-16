rule TTP_XOR_MULT_DOSStub_0a69 {
  strings:
    $key_0a69 = { 5e 01 [2] 2a 19 [2] 6d 1b [2] 2a 0a [2] 64 06 [2] 68 0c [2] 7f 07 [2] 64 49 [2] 59 }

  condition:
    any of them
}