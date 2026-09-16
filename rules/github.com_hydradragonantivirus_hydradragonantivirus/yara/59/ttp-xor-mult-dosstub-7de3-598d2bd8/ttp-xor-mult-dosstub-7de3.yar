rule TTP_XOR_MULT_DOSStub_7de3 {
  strings:
    $key_7de3 = { 29 8b [2] 5d 93 [2] 1a 91 [2] 5d 80 [2] 13 8c [2] 1f 86 [2] 08 8d [2] 13 c3 [2] 2e }

  condition:
    any of them
}