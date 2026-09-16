rule TTP_XOR_MULT_DOSStub_86e8 {
  strings:
    $key_86e8 = { d2 80 [2] a6 98 [2] e1 9a [2] a6 8b [2] e8 87 [2] e4 8d [2] f3 86 [2] e8 c8 [2] d5 }

  condition:
    any of them
}