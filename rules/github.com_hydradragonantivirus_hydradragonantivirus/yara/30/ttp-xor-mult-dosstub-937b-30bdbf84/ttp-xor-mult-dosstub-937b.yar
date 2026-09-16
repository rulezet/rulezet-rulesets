rule TTP_XOR_MULT_DOSStub_937b {
  strings:
    $key_937b = { c7 13 [2] b3 0b [2] f4 09 [2] b3 18 [2] fd 14 [2] f1 1e [2] e6 15 [2] fd 5b [2] c0 }

  condition:
    any of them
}