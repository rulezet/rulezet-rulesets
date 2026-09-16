rule TTP_XOR_MULT_DOSStub_937a {
  strings:
    $key_937a = { c7 12 [2] b3 0a [2] f4 08 [2] b3 19 [2] fd 15 [2] f1 1f [2] e6 14 [2] fd 5a [2] c0 }

  condition:
    any of them
}