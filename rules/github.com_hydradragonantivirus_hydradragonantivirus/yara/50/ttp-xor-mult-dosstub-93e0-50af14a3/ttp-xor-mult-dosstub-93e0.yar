rule TTP_XOR_MULT_DOSStub_93e0 {
  strings:
    $key_93e0 = { c7 88 [2] b3 90 [2] f4 92 [2] b3 83 [2] fd 8f [2] f1 85 [2] e6 8e [2] fd c0 [2] c0 }

  condition:
    any of them
}