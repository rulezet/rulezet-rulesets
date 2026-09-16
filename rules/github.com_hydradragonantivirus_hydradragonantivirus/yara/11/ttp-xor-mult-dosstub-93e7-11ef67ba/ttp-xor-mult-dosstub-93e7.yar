rule TTP_XOR_MULT_DOSStub_93e7 {
  strings:
    $key_93e7 = { c7 8f [2] b3 97 [2] f4 95 [2] b3 84 [2] fd 88 [2] f1 82 [2] e6 89 [2] fd c7 [2] c0 }

  condition:
    any of them
}