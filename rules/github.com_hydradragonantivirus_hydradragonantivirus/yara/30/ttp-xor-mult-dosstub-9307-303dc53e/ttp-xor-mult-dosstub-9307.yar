rule TTP_XOR_MULT_DOSStub_9307 {
  strings:
    $key_9307 = { c7 6f [2] b3 77 [2] f4 75 [2] b3 64 [2] fd 68 [2] f1 62 [2] e6 69 [2] fd 27 [2] c0 }

  condition:
    any of them
}