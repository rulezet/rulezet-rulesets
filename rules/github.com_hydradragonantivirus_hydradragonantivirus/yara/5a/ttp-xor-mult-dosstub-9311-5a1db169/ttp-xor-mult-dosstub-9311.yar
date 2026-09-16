rule TTP_XOR_MULT_DOSStub_9311 {
  strings:
    $key_9311 = { c7 79 [2] b3 61 [2] f4 63 [2] b3 72 [2] fd 7e [2] f1 74 [2] e6 7f [2] fd 31 [2] c0 }

  condition:
    any of them
}