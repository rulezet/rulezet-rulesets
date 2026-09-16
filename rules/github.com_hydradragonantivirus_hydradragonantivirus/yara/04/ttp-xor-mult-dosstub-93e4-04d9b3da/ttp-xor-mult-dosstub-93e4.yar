rule TTP_XOR_MULT_DOSStub_93e4 {
  strings:
    $key_93e4 = { c7 8c [2] b3 94 [2] f4 96 [2] b3 87 [2] fd 8b [2] f1 81 [2] e6 8a [2] fd c4 [2] c0 }

  condition:
    any of them
}