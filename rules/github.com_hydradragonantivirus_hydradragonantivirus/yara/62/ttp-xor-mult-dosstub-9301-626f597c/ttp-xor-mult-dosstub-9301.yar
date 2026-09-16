rule TTP_XOR_MULT_DOSStub_9301 {
  strings:
    $key_9301 = { c7 69 [2] b3 71 [2] f4 73 [2] b3 62 [2] fd 6e [2] f1 64 [2] e6 6f [2] fd 21 [2] c0 }

  condition:
    any of them
}