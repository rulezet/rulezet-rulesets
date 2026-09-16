rule TTP_XOR_MULT_DOSStub_4de3 {
  strings:
    $key_4de3 = { 19 8b [2] 6d 93 [2] 2a 91 [2] 6d 80 [2] 23 8c [2] 2f 86 [2] 38 8d [2] 23 c3 [2] 1e }

  condition:
    any of them
}