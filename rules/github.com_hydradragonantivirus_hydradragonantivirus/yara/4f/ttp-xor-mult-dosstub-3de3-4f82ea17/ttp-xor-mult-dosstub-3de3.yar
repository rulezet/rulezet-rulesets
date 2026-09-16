rule TTP_XOR_MULT_DOSStub_3de3 {
  strings:
    $key_3de3 = { 69 8b [2] 1d 93 [2] 5a 91 [2] 1d 80 [2] 53 8c [2] 5f 86 [2] 48 8d [2] 53 c3 [2] 6e }

  condition:
    any of them
}