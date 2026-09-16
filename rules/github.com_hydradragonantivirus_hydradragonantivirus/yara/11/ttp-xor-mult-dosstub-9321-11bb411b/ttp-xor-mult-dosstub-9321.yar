rule TTP_XOR_MULT_DOSStub_9321 {
  strings:
    $key_9321 = { c7 49 [2] b3 51 [2] f4 53 [2] b3 42 [2] fd 4e [2] f1 44 [2] e6 4f [2] fd 01 [2] c0 }

  condition:
    any of them
}