rule TTP_XOR_MULT_DOSStub_9337 {
  strings:
    $key_9337 = { c7 5f [2] b3 47 [2] f4 45 [2] b3 54 [2] fd 58 [2] f1 52 [2] e6 59 [2] fd 17 [2] c0 }

  condition:
    any of them
}