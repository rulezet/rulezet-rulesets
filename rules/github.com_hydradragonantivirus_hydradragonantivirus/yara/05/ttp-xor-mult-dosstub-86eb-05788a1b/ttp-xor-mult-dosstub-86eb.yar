rule TTP_XOR_MULT_DOSStub_86eb {
  strings:
    $key_86eb = { d2 83 [2] a6 9b [2] e1 99 [2] a6 88 [2] e8 84 [2] e4 8e [2] f3 85 [2] e8 cb [2] d5 }

  condition:
    any of them
}