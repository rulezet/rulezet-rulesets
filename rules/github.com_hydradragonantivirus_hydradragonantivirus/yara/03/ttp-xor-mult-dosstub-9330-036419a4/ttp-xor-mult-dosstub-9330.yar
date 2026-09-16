rule TTP_XOR_MULT_DOSStub_9330 {
  strings:
    $key_9330 = { c7 58 [2] b3 40 [2] f4 42 [2] b3 53 [2] fd 5f [2] f1 55 [2] e6 5e [2] fd 10 [2] c0 }

  condition:
    any of them
}