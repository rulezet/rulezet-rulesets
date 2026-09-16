rule TTP_XOR_MULT_DOSStub_93e2 {
  strings:
    $key_93e2 = { c7 8a [2] b3 92 [2] f4 90 [2] b3 81 [2] fd 8d [2] f1 87 [2] e6 8c [2] fd c2 [2] c0 }

  condition:
    any of them
}