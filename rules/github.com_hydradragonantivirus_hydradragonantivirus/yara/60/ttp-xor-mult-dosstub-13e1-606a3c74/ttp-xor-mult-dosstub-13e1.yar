rule TTP_XOR_MULT_DOSStub_13e1 {
  strings:
    $key_13e1 = { 47 89 [2] 33 91 [2] 74 93 [2] 33 82 [2] 7d 8e [2] 71 84 [2] 66 8f [2] 7d c1 [2] 40 }

  condition:
    any of them
}