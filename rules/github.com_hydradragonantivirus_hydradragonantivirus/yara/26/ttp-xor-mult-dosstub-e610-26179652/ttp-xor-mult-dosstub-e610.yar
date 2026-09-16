rule TTP_XOR_MULT_DOSStub_e610 {
  strings:
    $key_e610 = { b2 78 [2] c6 60 [2] 81 62 [2] c6 73 [2] 88 7f [2] 84 75 [2] 93 7e [2] 88 30 [2] b5 }

  condition:
    any of them
}