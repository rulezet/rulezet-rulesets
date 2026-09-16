rule TTP_XOR_MULT_DOSStub_071f {
  strings:
    $key_071f = { 53 77 [2] 27 6f [2] 60 6d [2] 27 7c [2] 69 70 [2] 65 7a [2] 72 71 [2] 69 3f [2] 54 }

  condition:
    any of them
}