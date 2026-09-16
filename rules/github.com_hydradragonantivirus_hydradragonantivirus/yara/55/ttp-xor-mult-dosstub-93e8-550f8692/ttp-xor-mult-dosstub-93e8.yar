rule TTP_XOR_MULT_DOSStub_93e8 {
  strings:
    $key_93e8 = { c7 80 [2] b3 98 [2] f4 9a [2] b3 8b [2] fd 87 [2] f1 8d [2] e6 86 [2] fd c8 [2] c0 }

  condition:
    any of them
}