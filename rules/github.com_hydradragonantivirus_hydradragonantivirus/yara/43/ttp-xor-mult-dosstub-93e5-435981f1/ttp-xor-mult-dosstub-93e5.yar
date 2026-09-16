rule TTP_XOR_MULT_DOSStub_93e5 {
  strings:
    $key_93e5 = { c7 8d [2] b3 95 [2] f4 97 [2] b3 86 [2] fd 8a [2] f1 80 [2] e6 8b [2] fd c5 [2] c0 }

  condition:
    any of them
}