rule TTP_XOR_MULT_DOSStub_0de3 {
  strings:
    $key_0de3 = { 59 8b [2] 2d 93 [2] 6a 91 [2] 2d 80 [2] 63 8c [2] 6f 86 [2] 78 8d [2] 63 c3 [2] 5e }

  condition:
    any of them
}