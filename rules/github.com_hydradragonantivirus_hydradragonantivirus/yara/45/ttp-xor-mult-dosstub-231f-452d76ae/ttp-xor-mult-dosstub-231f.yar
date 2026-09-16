rule TTP_XOR_MULT_DOSStub_231f {
  strings:
    $key_231f = { 77 77 [2] 03 6f [2] 44 6d [2] 03 7c [2] 4d 70 [2] 41 7a [2] 56 71 [2] 4d 3f [2] 70 }

  condition:
    any of them
}