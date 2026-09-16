rule TTP_XOR_MULT_DOSStub_93e6 {
  strings:
    $key_93e6 = { c7 8e [2] b3 96 [2] f4 94 [2] b3 85 [2] fd 89 [2] f1 83 [2] e6 88 [2] fd c6 [2] c0 }

  condition:
    any of them
}